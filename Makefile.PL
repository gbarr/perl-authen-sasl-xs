# Do yourself a favour, and don't edit this file, see README for build instructions

use ExtUtils::MakeMaker;

my @inc;
my @lib;
my $define;

my @search = (
  [qw(/usr/local/include /usr/local/lib)], [qw(/usr/local/include /usr/local/lib64)],
  [qw(/opt/local/include /opt/local/lib)], [qw(/opt/local/include /opt/local/lib64)],
);

if (do_search("sasl2")) {
  $define = "-DSASL2";
}
else {
  do_search("sasl");
}


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
  'NAME'         => 'Authen::SASL::XS',
  'VERSION_FROM' => 'XS.pm',
  'PREREQ_PM'    => {
    Test::Simple => 0,
    Test::More   => 0,
    Authen::SASL => 2.08,
  },
  @inc    ? (INC    => "@inc")  : (),
  @lib    ? (LIBS   => "@lib")  : (),
  $define ? (DEFINE => $define) : (),
);

sub do_search {
  my $what = shift;

  foreach my $pair (@search) {
    my ($inc, $lib) = @$pair;
    my @libs = glob("$lib/lib$what.*") or next;

    push @lib, "-L$lib -l$what";
    push @inc, "-I$inc";
    return 1;
  }
  return 0;
}

package MY;

sub postamble {
  return <<'POD';

XS.pod: XS.xs
	@echo "!!! Developers: Do not edit the XS.pod, edit the XS.xs instead. !!!"
	@echo "Make will overwrite XS.pod."
	- podselect XS.xs > XS.pod
POD
}
