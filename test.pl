#
# $Header: /cvsroot/Net::EasyTCP/test.pl,v 1.17 2002/11/05 02:37:57 mina Exp $
#

BEGIN {
	$| = 1;
	select(STDERR);
	$| = 1;
	select(STDOUT);
	print "1..7\n";
	}
END {print "not ok 1\n" unless $loaded;}
use Net::EasyTCP;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.
#
#
# Because windows is such a crappy OS that does not support (well) a fork() or alarm(), we can not possibly
# run this test. (HOWEVER, THE MODULE STILL WORKS OK !) Sorry !
#
if ($^O =~ /win32/i) {
	for (2..7) {
		print "ok $_\n";
		}
	warn ("\n\nWARNING:  SINCE YOU'RE RUNNING WINDOWS, WE COULD NOT TRULY TEST CLIENT-SERVER FUNCTIONALITY WITHIN 1 PROCESS. ASSUMING TEST SUCCEEDED\n\n");
	warn ("\n\nTO PROPERLY TEST THIS MODULE, LOOK INTO THE /util/ SUBFOLDER OF THIS DISTRO AND MANYALLY RUN THE server.pl THERE, THEN CONCURRENTLY RUN THE client.pl\n\n");
	exit(0);
	}


my $num = 1;

sub res() {
	my $res = shift;
	my $desc = shift;
	$num++;
	if ($res) {
		print "ok $num\n";
		}
	else {
		print "not ok $num\n";
		warn "Error in test [$desc]: $@\n";
		die("ABORTING TEST\n");
		}
	}

&startclient();

&startserver();

sub startserver() {
	my $temp;
	my $server;

	$server = new Net::EasyTCP(
		mode				=>      "server",
		port            =>      2345,
		password			=>		"just another perl hacker",
		);
	&res ($server, "Create new server");

	$temp = $server->setcallback(
		data            =>      \&gotdata,
		connect         =>      \&connected,
		disconnect      =>      \&disconnected,
		);
	&res($temp, "Set callbacks");

	$server->start();
	}

sub startclient() {
	my $temp;
	my $pid;
	my $starttime;
	my $maxelapsed = "15";

	$pid= fork();
	if ($pid) {
		# I'm the parent
		return;
		}
	elsif ($pid == 0) {
		# I'm the client
		}
	else {
		die "ERROR: FAILED TO FORK A PROCESS FOR A CLIENT: $!\n";
		}
		
	$starttime = time;

	while ((time - $starttime) <= $maxelapsed) {
		$client = new Net::EasyTCP(
			mode				=>		"client",
			host				=>		'127.0.0.1',
			port				=>		2345,
			password			=>		"just another perl hacker",
			);
		if ($client) {
			last;
			}
		}
	$client || die "ERROR: CLIENT FAILED TO BE CREATED WITHIN $maxelapsed SECONDS: $@\n";

	$temp = $client->receive();
	($temp eq "SEND ME COMPLEX") || die "ERROR: CLIENT RECEIVED [$temp] INSTEAD OF [SEND ME COMPLEX]\n";

	$temp = $client->send({"complex"=>"data"})
		|| die "ERROR: CLIENT FAILED TO SEND HASH REFERENCE: $@\n";

	$temp = $client->close()
		|| die "ERROR: CLIENT FAILED TO CLOSE CONNECTION: $@\n";

	exit(0);
	}

sub connected() {
	my $client = shift;
	my $temp;
	&res($client, "Server received connection");
	$temp = $client->send("SEND ME COMPLEX");
	&res($temp, "Server send data from callback");
	}

sub gotdata() {
	my $client = shift;
	my $data = $client->data();
	&res($data->{complex} eq "data", "Server receive complex data");
	}

sub disconnected() {
	my $client = shift;
	&res($client, "Server received client disconnection");
	exit(0);
	}

