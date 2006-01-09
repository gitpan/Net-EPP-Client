#!/usr/bin/perl
# $Id: Makefile.PL,v 1.4 2006/01/09 13:32:43 gavin Exp $

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
