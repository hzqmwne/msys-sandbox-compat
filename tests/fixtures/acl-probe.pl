use strict;
use warnings;
use DynaLoader;
my $module = DynaLoader::dl_load_file($ARGV[0],1) or die DynaLoader::dl_error();
my $symbol = DynaLoader::dl_find_symbol($module,'dacl_probe') or die DynaLoader::dl_error();
my $probe = DynaLoader::dl_install_xsub('Dacl::probe',$symbol);
$probe->();
print "PERL-AFTER-MUTATION-PASS\n";
