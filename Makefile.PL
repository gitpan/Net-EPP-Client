#!/usr/bin/perl
# $Id: Makefile.PL,v 1.1.1.1 2005/03/07 11:31:58 gavin Exp $

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'		=> 'Net::EPP::Client',
    'VERSION_FROM'	=> 'lib/Net/EPP/Client.pm',
);
