# Copyright (c) 2005 CentralNic Ltd. All rights reserved. This program is
# free software; you can redistribute it and/or modify it under the same
# terms as Perl itself.
# 
# $Id: Client.pm,v 1.2 2005/03/07 17:17:07 gavin Exp $
package Net::EPP::Client;
use Carp;
use IO::Socket;
use IO::Socket::SSL;
use XML::Parser;
use vars qw($VERSION $XMLDOM $TMPDIR);
use File::Temp qw(tempdir tempfile);
use strict;

our $VERSION = '0.01';

=pod

=head1 NAME

Net::EPP::Client - a client library for the TCP transport for EPP, the Extensible Provisioning Protocol

=head1 SYNOPSIS

	#!/usr/bin/perl
	use Net::EPP::Client;
	use strict;

	my $epp = Net::EPP::Client->new(
		host	=> 'epp.registry.tld',
		port	=> 700,
		ssl	=> 1,
		dom	=> 1,
	);

	my $greeting = $epp->connect;

	$epp->send_frame('login.xml');

	my $answer = $epp->get_frame;

	$epp->send_frame('<epp><logout /></epp>');

	my $answer = $epp->get_frame;

=head1 DESCRIPTION

EPP is the Extensible Provisioning Protocol. EPP (defined in RFC 3730) is an
application layer client-server protocol for the provisioning and management of
objects stored in a shared central repository. Specified in XML, the protocol
defines generic object management operations and an extensible framework that
maps protocol operations to objects. As of writing, its only well-developed
application is the provisioning of Internet domain names, hosts, and related
contact details.

RFC 3734 defines a TCP based transport model for EPP, and this module
implements a client for that model. You can establish and manage EPP
connections and send and receive responses over this connection.

C<Net::EPP::Client> also provides some time-saving features, such as being able
to provide request and response frames as C<XML::DOM::Document> objects.

=cut

BEGIN {
	our $XMLDOM = 0;
	eval {
		use XML::DOM;
		$XMLDOM = 1;
	};

	our $TMPDIR = tempdir(CLEANUP => 1);
}

=pod

=head1 CONSTRUCTOR

	my $epp = Net::EPP::Client->new(PARAMS);

The constructor method creates a new EPP client object. It accepts a number of
parameters:

=over

=item * host

C<host> specifies the computer to connect to. This may be a DNS hostname or
an IP address.

=item * port

C<port> specifies the TCP port to connect to. This is usually 700.

=item * ssl

If the C<ssl> parameter is defined, then C<IO::Socket::SSL> will be used to
provide an encrypted connection. If not, then a plaintext connection will be
created.

=item * dom

If the C<dom> parameter is defined, then all response frames will be returned
as C<XML::DOM::Document> objects.

=back

=cut

sub new {
	my ($package, %params) = @_;

	croak("missing hostname")	if (!defined($params{'host'}));
	croak("missing port")		if (!defined($params{'port'}));

	my $self = {
		'host'	=> $params{'host'},
		'port'	=> $params{'port'},
		'ssl'	=> (defined($params{'ssl'}) ? 1 : 0),
		'dom'	=> (defined($params{'dom'}) ? 1 : 0),
	};

	if ($self->{'dom'} == 1) {
		if ($XMLDOM == 0) {
			croak("DOM requested but XML::DOM isn't available");

		} else {
			$self->{'dom_parser'} = XML::DOM::Parser->new;

		}
	}

	$self->{'xml_parser'} = XML::Parser->new;

	return bless($self, $package);
}

=pod

=head1 METHODS

	my $greeting = $epp->connect(%PARAMS);

This method establishes the TCP connection. You can use the C<%PARAMS> hash to
specify arguments that will be passed on to the constructors for
C<IO::Socket::INET> (such as a timeout) or C<IO::Socket::SSL> (such as
certificate information). See the relevant manpage for examples.

This method will C<croak()> if connection fails, so be sure to use C<eval()> if
you want to catch the error.

The return value for C<connect()> will be the EPP C<E<lt>greetingE<gt>> frame
returned by the server. Please note that the same caveat about blocking applies
to this method as to C<get_frame()> (see below).

=cut

sub connect {
	my ($self, %params) = @_;

	my $SocketClass = ($self->{'ssl'} == 1 ? 'IO::Socket::SSL' : 'IO::Socket::INET');

	$self->{'connection'} = $SocketClass->new(
		PeerAddr	=> $self->{'host'},
		PeerPort	=> $self->{'port'},
		Proto		=> 'tcp',
		Type		=> SOCK_STREAM,
		%params
	);

	if (!defined($self->{'connection'}) || $@ ne '') {
		croak("Connection to $self->{'host'}:$self->{'port'} failed: \"$@\"");

	} else {
		return $self->get_frame();

	}

}

=pod

	my $frame = $epp->get_frame();

This method returns an EPP response frame from the server. This may either be a
scalar filled with XML, or an C<XML::DOM::Document> object, depending on
whether you defined the C<dom> parameter to the constructor.

B<Important Note>: this method will block your program until it receives the
full frame from the server. That could be a bad thing for your program, so you
might want to consider using the C<alarm()> function to apply a timeout, like
so:

	my $timeout = 10; # ten seconds

	eval {
		local $SIG{ALRM} = sub { die "alarm\n" };
		alarm($timeout);
		my $frame = $epp->get_frame;
		alarm(0);
	};

	if ($@ ne '') {
		print "timed out\n";
	}

=cut

sub get_frame {
	my $self = shift;

	my $hdr;
	$self->{'connection'}->read($hdr, 4);

	my $answer;
	$self->{'connection'}->read($answer, (unpack('N', $hdr) - 4));

	return $self->get_return_value($answer);
};

sub get_return_value {
	my ($self, $xml) = @_;

	if ($self->{'dom'} != 1) {
		return $xml;

	} else {
		my $document;
		eval {
			my ($fh, $fname) = tempfile(DIR => $TMPDIR);
			$fh->print($xml);
			$fh->close;
			$document = $self->{'dom_parser'}->parsefile($fname);
			unlink($fname);
		};
		if (!defined($document) || $@ ne '') {
			chomp($@);
			croak("Frame from server wasn't well formed: \"$@\"\n\nThe XML looks like this:\n\n$xml\n\n");

		} else {
			return $document;

		}
	}
}

=pod

	$epp->send_frame($frame);

This sends a request frame to the server. C<$frame> may be one of:

=over

=item * a scalar containing XML

=item * a scalar containing a filename

=item * an C<XML::DOM::Document> object

=back

In the case of the first two, the XML will be checked for well-formedness
before being sent. If the XML isn't well formed, this method will C<croak()>.

=cut

sub send_frame {
	my ($self, $frame) = @_;

	my ($xml, $wfcheck);
	if (ref($frame) eq 'XML::DOM::Document') {
		$xml		= $frame->toString;
		$wfcheck	= 0;

	} elsif (-e $frame) {
		if (!open(FRAME, $frame)) {
			croak("Couldn't open file '$frame' for reading: $!");

		} else {
			$xml = join('', <FRAME>);
			close(FRAME);
			$wfcheck = 1;

		}

	} else {
		$xml		= $frame;
		$wfcheck	= 1;

	}

	if ($wfcheck == 1) {
		eval {
			$self->{'xml_parser'}->parse($xml);
		};

		if ($@ ne '') {
			chomp($@);
			croak("Frame wasn't well formed: \"$@\"\n\nThe XML looks like this:\n\n$xml\n\n");

		}

	}

	$self->{'connection'}->print(pack('N', length($xml) + 4).$xml);

	return 1;
}

=pod

	$epp->disconnect;

This closes the connection. An EPP server will always close a connection after
a C<E<lt>logoutE<gt>> frame has been received and acknowledged; this method
is provided to allow you to clean up on the client side, or close the
connection out of sync with the server.

=cut

sub disconnect {
	my $self = shift;
	$self->{'connection'}->close;
	return 1;
}

=pod

=head1 COPYRIGHT

This module is (c) 2005, CentralNic Ltd. This module is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=head1 TO DO

=over

=item * implement some command-specific stuff, so you can simply use methods like C<login()>, C<check()>, etc

=back

=head1 SEE ALSO

=over

=item * RFCs 3730 and RFC 3734, available from L<http://www.ietf.org/>.

=item * The CentralNic EPP site at L<http://www.centralnic.com/epp/>.

=back

=cut

1;
