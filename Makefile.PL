use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Net::EasyTCP',
    'VERSION_FROM' => 'EasyTCP.pm', # finds $VERSION
    'DISTNAME' => 'EasyTCP',
    'PREREQ_PM' => { 'IO::Socket'=>0, 'IO::Select'=>0, 'Storable'=>0 },
    'dist' => { COMPRESS => "gzip -9", SUFFIX => "gz" },
);

