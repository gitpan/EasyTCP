package Net::EasyTCP;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $SERIAL $SELECTOR);

use IO::Socket;
use IO::Select;
use Storable qw(nfreeze thaw);

require Exporter;
require AutoLoader;

@ISA = qw(Exporter AutoLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw();
$VERSION = '0.01';

# Preloaded methods go here.


#
# This takes an integer, packs it as tightly as possible as a binary representation
# and returns the binary value
#
sub _packint() {
	my $int = shift;
	my $bin;
        $bin = pack("N", $int);
        $bin =~ s/^\0+//;
	return $bin;
	}

#
# This does the opposite of _packint. It takes a packed binary produced by _packint and
# returns the integer
#
sub _unpackint() {
	my $bin = shift;
	my $int;
        $int = "\0" x (4-length($bin)) . $bin;
        $int = unpack("N", $int);
	return $int;
	}

#
# This creates a new client object that's already connected (the server creates 
# these when it accepts a new connection
#
sub _new_serverclient() {
	my $class = shift;
	my $sock = shift;
	my $self;
	$class =~ s/=.*//g;
	$self->{_sock} = $sock;
	$self->{_mode} = "serverclient";
	bless ($self, $class);
	return $self;
	}

#
# This creates a new client object and outgoing connection and returns it the object
# , or returns undef if unsuccessful
#
sub _new_client() {
	my $class = shift;
	my %para = @_;
	my $sock;
	my $self = {};
	if (!$para{host}) {
		$@ = "Invalid host";
		return undef;
		}
	elsif (!$para{port}) {
		$@ = "Invalid port";
		return undef;
		}
	$sock = new IO::Socket::INET(
		PeerAddr	=>	$para{host},
		PeerPort	=>	$para{port},
		Proto		=>	'tcp',
		Timeout		=>	30,
		);
	if (!$sock) {
		$@ = "Could not connect to $para{host}:$para{port}: $!";
		return undef;
		}
	$self->{_sock} = $sock;
	$self->{_mode} = "client";
	bless ($self, $class);
	return $self;
	}

#
# This creates a new listening server object and returns it, or returns undef if unsuccessful
#
sub _new_server() {
	my $class = shift;
	my %para = @_;
	my $sock;
	my $self = {};
	if (!$para{port}) {
		$@ = "Invalid port";
		return undef;
		}
	$sock = new IO::Socket::INET(
		LocalPort	=>	$para{port},
		Proto		=>	'tcp',
		Listen		=>	SOMAXCONN,
		Reuse		=>	1,
		);
	if (!$sock) {
		$@ = "Could not create listening socket on port $para{port}: $!";
		return undef;
		}
	$self->{_sock} = $sock;
	$self->{_mode} = "server";
	bless($self, $class);
	return $self;
	}

#
# This takes a reference to a scalar, extracts a fully qualified data out of it
# if possible, modifies the original scalar to what's left, and returns the extracted data
# If no valid data found, returns nothing
#
sub _extractdata() {
	my $ref = shift;
	my $key = substr($$ref, 0, 1);
	my ($alwayson, $complexstructure, $realdata, $reserved, $lenlen);
	my $lendata;
	my $len;
	my $data;
	if (!defined $key) {
		return undef;
		}
	$alwayson		=	vec($key, 0, 1);
	$complexstructure	=	vec($key, 1, 1);
	$realdata		=	vec($key, 2, 1);
	$reserved		=	vec($key, 3, 1);
	$lenlen			=	vec($key, 1, 4);
	if (!$alwayson) {
		return undef;
		}
	$len = substr($$ref, 1, $lenlen);
	$lendata = &_unpackint($len);
	if (length($$ref) < (1+$lenlen+$lendata)) {
		return undef;
		}
	$data = substr($$ref, 1+$lenlen, $lendata);
	if (length($data) != $lendata) {
		return undef;
		}
	substr($$ref, 0, 1 + $lenlen + $lendata, '');
	if ($complexstructure) {
		$data = thaw($data);
		if (!$data) {
			$@ = "Error decompressing complex structure: $!";
			$data = undef;
			}
		}
	return $data;
	}

#
# This takes a socket handle and data and sends the data to the socket
# Returns 1 for success, undef on failure
#
sub _send() {
	my $sock = shift;
	my $data = shift;
	my $lendata;
	my $lenlen;
	my $len;
	my $key = chr(0);
	my $packet;
	my $complexstructure = ref($data);
	if ($complexstructure) {
		$data = nfreeze $data;
		}
	$lendata = length($data);
	$len = &_packint($lendata);
	$lenlen = length($len);
	vec($key, 0, 1) = 1;
	vec($key, 1, 1) = ($complexstructure) ? 1 : 0;
	vec($key, 2, 1) = 1;
	vec($key, 3, 1) = 0;
	vec($key, 1, 4) = $lenlen;
	$packet = $key . $len . $data;
	syswrite($sock, $packet, length($packet));
	return 1;
	}


# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Net::EasyTCP - Easily create TCP/IP clients and servers via an OO interface and event callbacks

=head1 SYNOPSIS

B<SERVER EXAMPLE:>

  use Net::EasyTCP;

  $server = new Net::EasyTCP(
	mode            =>      "server",
	port            =>      2345,
	)
	|| die "ERROR CREATING SERVER: $@\n";

  $server->callback(
	data            =>      \&gotdata,
	connect         =>      \&connected,
	disconnect	=>	\&disconnected,
	)
	|| die "ERROR SETTING CALLBACKS: $@\n";

  $server->start() || die "ERROR STARTING SERVER: $@\n";

  sub gotdata() {
	my $client = shift;
	my $serial = $client->serial();
	my $data = $client->data();
	print "Client $serial sent me some data, sending it right back to them again\n";
	$client->send($data) || die "ERROR SENDING TO CLIENT: $@\n";
	if ($data eq "QUIT") {
		$client->close() || die "ERROR CLOSING CLIENT: $@\n";
		}
	elsif ($data eq "DIE") {
		$server->stop() || die "ERROR STOPPING SERVER: $@\n";
		}
	}

  sub connected() {
	my $client = shift;
	my $serial = $client->serial();
	print "Client $serial just connected\n";
	}

  sub disconnected() {
	my $client = shift;
	my $serial = $client->serial();
	print "Client $serial just disconnected\n";
	}


B<CLIENT EXAMPLE:>

  use Net::EasyTCP;

  $client = new Net::EasyTCP(
	mode            =>      "client",
	host            =>      'localhost',
	port            =>      2345,
	)
	|| die "ERROR CREATING CLIENT: $@\n";

  #Send and receive a simple string
  $client->send("HELLO THERE") || die "ERROR SENDING: $@\n";
  $reply = $client->receive() || die "ERROR RECEIVING: $@\n";

  #Send and receive complex objects/strings/arrays/hashes by reference
  %hash = ("to be or" => "not to be" , "just another" => "perl hacker");
  $client->send(\%hash) || die "ERROR SENDING: $@\n";
  $reply = $client->receive() || die "ERROR RECEIVING: $@\n";
  foreach (keys %{$reply}) {
	print "Received key: $_ = $reply->{$_}\n";
	}

  #Send and receive large binary data
  for (1..4096) {
	for (0..255) {
		$largedata .= chr($_);
		}
	}
  $client->send($largedata) || die "ERROR SENDING: $@\n";
  $reply = $client->receive() || die "ERROR RECEIVING: $@\n";

  $client->close();

=head1 DESCRIPTION

This class allows you to easily create TCP/IP clients and servers and provides an OO interface to manage the connection(s).  This allows you to concentrate on the application rather than on the transport.

You still have to engineer your high-level protocol. For example, if you're writing an SMTP client-server pair, you will have to teach your client to send "HELO" when it connects, and you will have to teach your server what to do once it receives the "HELO" command, and so forth.

What you won't have to do is worry about how the command will get there, about line termination, about binary data, complex-structure serialization, or about fragmented packets on the received end.  All of these will be taken care of by this class.

=head1 CONSTRUCTOR

B<new(%hash)>

Constructs and returns a new Net::EasyTCP object.  Such an object behaves in one of two modes (that needs to be supplied to new() on creation time).  You can create either a server object (which accepts connections from several clients) or a client object (which initiates a connection to a server).

new() expects to be passed a hash. The following keys are accepted:

=over 4

=item mode

Must be set to either "client" or "server" according to the type of object you want returned.
(Mandatory)

=item port

Must be set to the port the client connects to (if mode is "client") or to the port to listen to (if mode is "server"). If you're writing a client+server pair, they must both use the same port number.
(Mandatory)

=item host

Must be set to the hostname/IP address to connect to.
(Mandatory when mode is "client")

=back

=head1 METHODS

B<[C] = Available to objects created as mode "client">

B<[S] = Available to objects created as mode "server">

=over 4

=item callback(%hash)

B<[S]> Tells the server which subroutines to call when specific events happen. For example when a client sends the server data, the server calls the "data" callback sub.

callback() expects to be passed a hash. Each key in the hash is the callback type identifier, and the value is a reference to a sub to call once that callback type event occurs.

Valid keys in that hash are:

=over 4

=item connect

Called when a new client connects to the server

=item data

Called when an existing client sends data to the server

=item disconnect

Called when an existing client disconnects

=back

Whenever a callback sub is called, it is passed a single parameter, a CLIENT OBJECT. The callback code may then use any of the methods available to client objects to do whatever it wants to do (Read data sent from the client, reply to the client, close the client connection etc...)

=item close()

B<[C]> Instructs a client object to close it's connection with a server.

=item data()

B<[C]> Retrieves the previously-retrieved data associated with a client object.  This method is typically used from inside the callback sub associated with the "data" event, since the callback sub is passed nothing more than a client object.

=item disconnect()

See close()

=item mode()

B<[C][S]> Identifies the mode of the object.  Returns either "client" or "server"

=item receive()

B<[C]> Receives data sent to the client by a server and returns it.  It will block until data is received or until 300 seconds of inactivity have elapsed.

=item running()

B<[S]> Returns true if the server is running (started), false if it is not.

=item send($data)

B<[C]> Sends data to a server.  It can be used on client objects you create with the new() constructor, or with client objects passed to your callback subs by a running server.

It accepts one parameter, and that is the data to send.  The data can be a simple scalar or a reference to something more complex.

=item serial()

B<[C]> Retrieves the serial number of a client object,  This is a simple integer that allows your callback subs to easily differentiate between different clients.

=item start()

B<[S]> Starts a server and does NOT return until the server is stopped via the stop() method.  Once a server is started it will accept new client connections as well as parse incoming data from clients and fire off the appropriate callbacks' subs.

=item stop()

B<[S]> Instructs a running server to stop and returns immediately (does not wait for the server to actually stop, which may be a few seconds later).  To check if the server is still running or not use the running() method.

=back

=head1 RETURN VALUES AND ERRORS

The constructor and all methods return something that evaluates to true when successful, and to false when not successful.

The only exception to the above rule is the data() method.  If the data received is an empty string or the string "0" then it will evaluate to false which is probably not what you want.  In that case check that the data you just read is defined.

If not successful, the variable $@ will contain a description of the error that occurred.

=head1 NOTES

=over 4

=item Internal Protocol

This class implements a miniature protocol when it sends and receives data between it's clients and servers.  This means that a server created using this class cannot properly communicate with a normal client of any protocol (pop3/smtp/etc..) unless that client was also written using this class.  It also means that a client written with this class will not properly communicate with a different server (telnet/smtp/pop3 server for example, unless that server is implemented using this class also).  This limitation may change in future releases.

In other words, if you write a server using this class, write the client using this class also, and vice versa.

=item Deadlocks

As with any client-server scenario, make sure you engineer how they're going to talk to each other, and the order they're going to talk to each other in, quite carefully.  If both ends of the connection are waiting for the other end to say something, you've got a deadlock.

=back

=head1 TO DO

=over 4

=item *

Make the client object work with other servers not written with this class, and vice versa. (automatic protocol detection)

=item *

Implement optional compression. (transparently compress and decompress client-server communications)

=item *

Implement optional encryption. (transparently secure client-server communications)

=back

=head1 AUTHOR

Mina Naguib, mnaguib@cpan.org

=head1 SEE ALSO

IO::Socket

=cut

#
# The main constructor. This calls either _new_client or _new_server depending on the supplied mode
#
sub new() {
	my $class = shift;
	my %para = @_;
	if ($para{mode} =~ /^c/i) {
		return &_new_client($class, %para);
		}
	elsif ($para{mode} =~ /^s/i) {
		return &_new_server($class, %para);
		}
	else {
		$@ = "Supplied mode '$para{mode}' unacceptable. Must be either 'client' or 'server'";
		return undef;
		}
	}

#
# This method modifies the _callback_XYZ in a server object. These are the routines
# the server calls when an event (data, connect, disconnect) happens
#
sub callback() {
	my $self = shift;
	my %para = @_;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method callback()";
		return undef;
		}
	foreach (keys %para) {
		if (!exists $para{$_}) {
			$@ = "Callback $_ $para{$_} does not exist";
			return 0;
			}
		$self->{"_callback_$_"} = $para{$_};
		}
	return 1;
	}

#
# This method starts the server and does not return
# The server then listens for new connections as well as accepts data from existing connections
# And fires off any necessary callback events when necessary
#
sub start() {
	my $self = shift;
	my @ready;
	my $clientsock;
	my %clientobject;
	my $tempdata;
	my $data;
	my $result;
	my $error;
	$SELECTOR = new IO::Select;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method start()";
		return undef;
		}
	$self->{_running} = 1;
	$self->{_requeststop} = 0;
	$SELECTOR->add($self->{_sock});
MLOOP:	while (!$self->{_requeststop}) {
		@ready = $SELECTOR->can_read(2);
		foreach (@ready) {
			if ($_ == $self->{_sock}) {
				# The SERVER SOCKET is ready for
				$clientsock = $self->{_sock}->accept();
				if (!$clientsock) {
					$error = "Error while accepting new connection: $!";
					last MLOOP;
					}
				$SERIAL++;
				$SELECTOR->add($clientsock);
				$clientobject{$clientsock} = &_new_serverclient($self, $clientsock);
				$clientobject{$clientsock}->{_serial} = $SERIAL;
				&{$self->{_callback_connect}}($clientobject{$clientsock}) if ($self->{_callback_connect});
				}
			else {
				# One of the client sockets are ready
				$result = sysread($_, $tempdata, 65536);
				if (!defined $result) {
					# Error somewhere during reading
					&{$self->{_callback_disconnect}}($clientobject{$_}) if ($self->{_callback_disconnect});
					$clientobject{$_}->close();
					delete $clientobject{$_};
					}
				elsif ($result == 0) {
					# Client closed connection
					&{$self->{_callback_disconnect}}($clientobject{$_}) if ($self->{_callback_disconnect});
					$clientobject{$_}->close();
					delete $clientobject{$_};
					}
				else {
					# Client sent us some good data
					$clientobject{$_}->{_databuffer} .= $tempdata;
					while ($clientobject{$_}->{_data} = &_extractdata(\$clientobject{$_}->{_databuffer})) {
						&{$self->{_callback_data}}($clientobject{$_}) if ($self->{_callback_data});
						}
					}
				}
			}
		}
	$self->{_running} = 0;
	if ($error) {
		$@ = $error;
		return undef;
		}
	else {
		return 1;
		}
	}

#
# This method stops the server and makes it return.
# Note: It doesn't stop the server immediately, it sets a flag
# and the flag should in a few seconds cause the infinite loop in start() method to stop
#
sub stop() {
	my $self = shift;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot call method stop()";
		return undef;
		}
	$self->{_requeststop} = 1;
	return 1;
	}

#
# This method sends data to the socket associated with the object
#
sub send() {
	my $self = shift;
	my $data = shift;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method send()";
		return undef;
		}
	return &_send($self->{_sock}, $data);
	}

#
# This method returns the serial number associated with the object
#
sub serial() {
	my $self = shift;
	if (!$self->{_serial}) {
		$self->{_serial} = ++$SERIAL;
		}
	return $self->{_serial};
	}

#
# This method returns the already-read data associated with the object
# (typically the code in the callback assigned to callback_data would access this method)
#
sub data() {
	my $self = shift;
	return $self->{_data};
	}

#
# This method reads data from the socket associated with the object and returns it
#
sub receive() {
	my $self = shift;
	my $temp;
	my $data;
	my $result;
	my $lastactivity = time;
	my $timeout = 300;
	if ($self->{_mode} ne "client") {
		$@ = "$self->{_mode} cannot use method receive()";
		return undef;
		}
	while ((time - $lastactivity) < $timeout) {
		$result = sysread($self->{_sock}, $temp, 65536);
		if ($result == 0) {
			# Socket closed
			$@ = "Socket closed when attempted reading";
			return undef;
			}
		elsif (!defined $result) {
			# Error in socket
			$@ = "Error reading from socket: $!";
			return undef;
			}
		else {
			# Read good data
			$lastactivity = time;
			$self->{_databuffer} .= $temp;
			$data = &_extractdata(\$self->{_databuffer});
			if (defined $data) {
				return $data;
				}
			}
		}
	$@ = "Timed out waiting to receive data";
	return undef;
	}

#
# This method is a synonym for close()
#
sub disconnect() {
	return &close(@_);
	}

#
# This method closes the socket associated with the object
#
sub close() {
	my $self = shift;
	if ($self->{_mode} ne "client" && $self->{_mode} ne "serverclient") {
		$@ = "$self->{_mode} cannot use method close()";
		return undef;
		}
	if ($SELECTOR && $SELECTOR->exists($self->{_sock})) {
		# If the server selector reads this, let's make it not...
		$SELECTOR->remove($self->{_sock});
		}
	$self->{_sock}->close();
	$self->{_sock} = undef;
	return 1;
	}

#
# This method returns true or false, depending on if the server is running or not
#
sub running() {
	my $self = shift;
	if ($self->{_mode} ne "server") {
		$@ = "$self->{_mode} cannot use method running()";
		return undef;
		}
	return $self->{_running};
	}

#
# This replies saying what type of object it's passed
#
sub mode() {
	my $self = shift;
	my $mode = ($self->{_mode} eq "server") ? "server" : "client";
	return $mode;
	}
