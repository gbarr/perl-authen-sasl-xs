#
# Add SASL encoding/decoding to a filehandle
#

package Authen::SASL::Cyrus::Security;


sub TIEHANDLE {
  my($class, $fh, $conn) = @_;
  my($ref);

  $ref->{fh} = $fh;
  $ref->{conn} = $conn;

  bless($ref,$class);
  return($ref);
}




sub FILENO {
  my($ref) = @_;
  return(fileno($ref->{fh}));
}




sub READ {
  my($ref, $buf, $len, $offset) = @_;
  my($need, $didread, $fh, $rc, $cryptbuf, $clearbuf);

  $fh = $ref->{fh};
  $buf = \$_[1];

  # Check if there's leftovers from a previous READ
  $need = $len;
  if ($ref->{readbuf}) {
    # If there's enough in the buffer, just take from there
    if (length($ref->{readbuf}) >= $len) {
      substr($$buf, $offset, $len) = substr($ref->{readbuf}, 0, $len);
      $ref->{readbuf} = substr($ref->{readbuf}, $len);
      return($len);
    }

    # Not enough. Take all of the buffer, and read more
    substr($$buf, $offset, $len) = $ref->{readbuf};
    $didread = length($ref->{readbuf});
    $need -= $didread;
    $offset += $didread;
    $ref->{readbuf} = "";
  }

  # Read in bytes from the socket, and decrypt it
  $rc = sysread($fh, $cryptbuf, $len);
  return($didread) if ($rc <= 0);
  $clearbuf = $ref->{conn}->decode($cryptbuf);
  return(-1) if ($clearbuf eq undef);

  # It may be that more encrypted bytes are needed to decrypt an entire "block"
  # If decode() returned nothing, read in more bytes (arbitrary amounts) until
  # an entire encrypted block is available to decrypt.
  while ($clearbuf eq "") {
    $rc = sysread($fh, $cryptbuf, 8);
    return($rc) if ($rc <= 0);
    $clearbuf = $ref->{conn}->decode($cryptbuf);
    return(-1) if ($clearbuf eq undef);
  }

  # Copy what was asked for, stash the rest
  substr($$buf, $offset, $need) = substr($clearbuf, 0, $need);
  $ref->{readbuf} = substr($clearbuf, $need);

  return($len);
}




# Encrypting a write() to a filehandle is much easier than reading, because
# all the data to be encrypted is immediately available
sub WRITE {
  my($ref,$string,$len) = @_;
  my($fh, $clearbuf, $cryptbuf);

  $fh = $ref->{fh};
  $clearbuf = substr($string, 0, $len);
  $cryptbuf = $ref->{conn}->encode($clearbuf);
  print $fh $cryptbuf;
}




# Given a GLOB ref, tie the filehandle of the GLOB to this class
sub new {
  my($class, $fh, $conn) = @_;
  tie(*{$fh}, $class, $fh, $conn);
}




# Avoid getting too circular in the free'ing of an object in this class.
sub DESTROY {
  my($self) = @_;
  delete($self->{fh});
  undef $self;
}

1;
