# Do yourself a favour, and don't edit this file, see README for build instructions

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Authen::SASL::Cyrus',
    'VERSION_FROM' => 'Cyrus.pm',
	'PREREQ_PM'		=> {
		Test::Simple => 0,
		Test::More	=> 0,
		Authen::SASL => 2.07,
	},
);

package MY;
sub manifypods
{
	return <<'POD';
manifypods: Cyrus.pod

Cyrus.pod: Cyrus.xs
		@echo "!!! Developers: Do not edit the Cyrus.pod, edit the Cyrus.xs instead. !!!"
		@echo "Make will overwrite Cyrus.pod."
		podselect Cyrus.xs > Cyrus.pod
POD
}
