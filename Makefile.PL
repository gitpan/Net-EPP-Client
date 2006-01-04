#!/usr/bin/perl
# $Id: Makefile.PL,v 1.3 2006/01/04 12:35:55 gavin Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'			=> 'Net::EPP::Client',
    'VERSION_FROM'		=> 'lib/Net/EPP/Client.pm',
    'PREREQ_PM'			=> {
        'IO::Socket'		=> 0,
        'IO::Socket::SSL'	=> 0,
        'XML::Parser'		=> 0,
        'File::Temp'		=> 0,
    },
);
