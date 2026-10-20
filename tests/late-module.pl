use strict;
use warnings;
no warnings 'portable';
use DynaLoader;
use POSIX qw(_exit WIFEXITED WEXITSTATUS);

my $helper = DynaLoader::dl_load_file($ARGV[1], 1) or die DynaLoader::dl_error();
my $module = DynaLoader::dl_load_file($ARGV[0], 1) or die DynaLoader::dl_error();
my $symbol = DynaLoader::dl_find_symbol($module, 'late_probe') or die DynaLoader::dl_error();
die "late DLL was randomized: $symbol" unless $symbol >= 0x63000000000 && $symbol < 0x63001000000;
my $function = DynaLoader::dl_install_xsub('Late::probe', $symbol);
$function->();
my $pid = fork();
die "fork: $!" unless defined $pid;
if (!$pid) {
    my $inherited = DynaLoader::dl_find_symbol($module, 'late_probe');
    _exit(85) unless $inherited == $symbol;
    $function->();
    _exit(23);
}
waitpid($pid, 0);
die "late DLL fork failed: $?" unless WIFEXITED($?) && WEXITSTATUS($?) == 23;
print "LATE-DLL-FORK-PASS\n";
