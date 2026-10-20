use strict;
use warnings;
use Test::More;
use POSIX qw(_exit WIFEXITED WEXITSTATUS WIFSIGNALED WTERMSIG WNOHANG);
use Fcntl qw(:DEFAULT :seek);
$|=1;
my $parent=$$;
my @heap=map { "entry-$_-" . ('x' x 1024) } 1..256;
my $value='parent';
my $pid=fork();
die "fork: $!" unless defined $pid;
if(!$pid){$value='child';_exit($$!=$parent && $heap[255]=~/entry-256-/ ? 17:90);}
ok($pid>0,'parent receives a positive child PID');
is(waitpid($pid,0),$pid,'waitpid returns the child PID');
is(WEXITSTATUS($?),17,'child receives zero and has copied heap, distinct PID, correct exit status');
is($value,'parent','child writes do not change parent memory');

pipe(my $reader,my $writer) or die "pipe: $!";
$pid=fork();die "fork: $!" unless defined $pid;
if(!$pid){close $reader;print $writer 'pipe-from-child';close $writer;_exit(0);}
close $writer;my $message=do { local $/; <$reader> };close $reader;
waitpid($pid,0);is($message,'pipe-from-child','pipe descriptors and EOF work across fork');

my $file="fork-offset-$$.tmp";
sysopen(my $fd,$file,O_CREAT|O_TRUNC|O_RDWR,0600) or die "open: $!";
syswrite($fd,'abcdef');sysseek($fd,0,SEEK_SET);
$pid=fork();die "fork: $!" unless defined $pid;
if(!$pid){my $s;sysread($fd,$s,2);_exit($s eq 'ab'?0:91);}
waitpid($pid,0);my $s;sysread($fd,$s,2);close $fd;unlink $file;
is($s,'cd','inherited file description shares the file offset');

pipe(my $ready_r,my $ready_w) or die $!;
$pid=fork();die "fork: $!" unless defined $pid;
if(!$pid){close $ready_r;$SIG{USR1}=sub{_exit(23)};syswrite($ready_w,'R');close $ready_w;sleep 10;_exit(92);}
close $ready_w;sysread($ready_r,$s,1);close $ready_r;
is(kill('USR1',$pid),1,'signal is delivered to another POSIX process');
waitpid($pid,0);is(WEXITSTATUS($?),23,'installed signal handler runs in child');

$pid=fork();die "fork: $!" unless defined $pid;
if(!$pid){exec('/usr/bin/true') or _exit(93);}
waitpid($pid,0);ok(WIFEXITED($?)&&WEXITSTATUS($?)==0,'fork followed by exec works');

$pid=fork();die "fork: $!" unless defined $pid;
if(!$pid){sleep 10;_exit(96);}
is(waitpid($pid,WNOHANG),0,'WNOHANG does not reap a live child');
kill('TERM',$pid);waitpid($pid,0);
ok(WIFSIGNALED($?)&&WTERMSIG($?)==15,'default SIGTERM and wait signal status work');

pipe(my $exec_r,my $exec_w) or die $!;
$pid=fork();die "fork: $!" unless defined $pid;
if(!$pid){close $exec_r;open(STDOUT,'>&',$exec_w) or _exit(97);close $exec_w;exec('/usr/bin/printf','fd-exec') or _exit(98);}
close $exec_w;$message=do{local $/;<$exec_r>};close $exec_r;waitpid($pid,0);
is($message,'fd-exec','dup2-like stdout redirection survives exec');

$pid=fork();die "fork: $!" unless defined $pid;
if(!$pid){my $grandchild=fork();_exit(94) unless defined $grandchild;if(!$grandchild){_exit(29)}waitpid($grandchild,0);_exit(WEXITSTATUS($?)==29?0:95);}
waitpid($pid,0);is(WEXITSTATUS($?),0,'nested fork and wait work');

my @children;
for my $index (1..32){my $p=fork();die "parallel fork $index: $!" unless defined $p;if(!$p){_exit($index%16)}push @children,[$p,$index%16];}
my $good=0;for my $c (@children){my $p=waitpid($c->[0],0);$good++ if $p==$c->[0]&&WIFEXITED($?)&&WEXITSTATUS($?)==$c->[1];}
is($good,32,'32 concurrent children retain individual identities and statuses');

require threads;
my $thread_repetitions=@ARGV ? int($ARGV[0]) : 1;
die "thread repetitions must be 1..1000" if $thread_repetitions<1 || $thread_repetitions>1000;
for (1..$thread_repetitions) {
my $thread=threads->create(sub{my $p=fork();return -1 unless defined $p;if(!$p){_exit(31)}waitpid($p,0);return WEXITSTATUS($?);});
is($thread->join(),31,'fork from a secondary POSIX thread works');
}
done_testing();
