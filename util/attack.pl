#!/usr/bin/perl

#
# $Header: /cvsroot/Net::EasyTCP/util/attack.pl,v 1.2 2002/11/03 09:06:18 mina Exp $
#

$|=1;

use Net::EasyTCP;
$|=1;

for (1..1000) {
	print "Launching client [$_}\n";
  $client = new Net::EasyTCP(
        mode            =>      "client",
        host            =>      'localhost',
        port            =>      2345,
		password			=>	"byteme",
		donotencrypt	=>	1,
        )
        || die "ERROR CREATING CLIENT: $@\n";
	push (@clients, $client);
	}

foreach $client (@clients) {
	print "Closing ...\n";
	$client->close() || die "ERROR CLOSING: $@\n";
	}
