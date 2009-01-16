# Do yourself a favour, and don't edit this file, see README for build instructions

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Authen::SASL::XS',
    'VERSION_FROM' => 'XS.pm',
	'PREREQ_PM'		=> {
		Test::Simple => 0,
		Test::More	=> 0,
		Authen::SASL => 2.08,
	},
);

package MY;
sub manifypods
{
	return <<'POD';
manifypods: XS.pod

XS.pod: XS.xs
		@echo "!!! Developers: Do not edit the XS.pod, edit the XS.xs instead. !!!"
		@echo "Make will overwrite XS.pod."
		podselect XS.xs > XS.pod
POD
}
