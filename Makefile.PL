#!/usr/bin/perl
# $Id: Makefile.PL,v 1.2 2005/03/10 12:44:59 gavin Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'			=> 'Net::EPP::Client',
    'VERSION_FROM'		=> 'lib/Net/EPP/Client.pm',
    'PREREQ_PM'			=> {
        'IO::Socket'		=> 0,
        'IO::Socket::SSL'	=> 0,
        'XML::Parser'		=> 0,
    },
);
