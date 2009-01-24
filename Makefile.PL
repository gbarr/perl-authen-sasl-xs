# Do yourself a favour, and don't edit this file, see README for build instructions

use lib 'inc';
use ExtUtils::MakeMaker;
use Devel::CheckLib;

my @inc_search = qw(/opt/local/include /usr/local/include);
my @lib_search = qw(/opt/local/lib64 /usr/local/lib64 /opt/local/lib /usr/local/lib);
my %args       = map {/^(\w+)=(.*)/} grep {/^\w+=/} @ARGV;
my $use_sasl2  = exists $args{DEFINE} and $args{DEFINE} =~ /-DSASL2/;
my %mmopt;

unless (exists $args{INC} or exists $args{LIB}) {

  my @incpath = grep {-d} @inc_search;
  my @libpath = grep {-d} @lib_search;
  my $have_sasl2 = eval {
    assert_lib(
      lib     => "sasl2",
      header  => "sasl/sasl.h",
      libpath => \@libpath,
      incpath => \@incpath
    );
    1;
  };

  if ($have_sasl2) {
    $mmopt{DEFINE} = "-DSASL2" unless $use_sasl2;
  }
  else {
    exit(0) if $use_sasl2;
    @incpath = grep {-d} map { ("$_/sasl", $_) } @inc_search;
    check_lib_or_exit(
      lib     => "sasl",
      header  => "sasl.h",
      libpath => \@libpath,
      incpath => \@incpath
    );
  }

  $mmopt{INC}  = join " ", map {"-I$_"} @incpath;
  $mmopt{LIBS} = join " ", map {"-L$_"} @libpath;
  $mmopt{LIBS} .= $have_sasl2 ? " -lsasl2" : " -lsasl";
}

WriteMakefile(
  'NAME'         => 'Authen::SASL::XS',
  'VERSION_FROM' => 'XS.pm',
  'PREREQ_PM'    => {
    Test::Simple => 0,
    Test::More   => 0,
    Authen::SASL => 2.08,
  },
  %mmopt,
);

package MY;

sub postamble {
  return <<'POD';

XS.pod: XS.xs
	@echo "!!! Developers: Do not edit the XS.pod, edit the XS.xs instead. !!!"
	@echo "Make will overwrite XS.pod."
	- podselect XS.xs > XS.pod
POD
}


sub metafile {
  my $self = shift;
  my $pkg  = ref($self) || $self;
  my $echo = $self->can('echo');

  # This is not supported by MM, but locally override ->echo to add to META.yml
  local *{"${pkg}::echo"} = sub {
    my ($self, $what, $target) = @_;
    if ($target eq 'META_new.yml') {
      $what .= <<EXTRA_META;
no_index:
  directory:
    - inc
    - t
EXTRA_META
    }
    $self->$echo($what, $target);
  };
  $self->metafile_target(@_);
}

