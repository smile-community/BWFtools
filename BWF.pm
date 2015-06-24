#!/usr/bin/perl
#
# ident "@(#)$Header: BWF.pm,v 1.15 2015/06/07 23:02:26 gs Exp $"
#
# Copyright 2015 (c) guenther.schreiner@smile.de
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#
# Description:
#      Barracuda Webfilter interface script for accessing syslog files
#
#
#       - BWF::parse_log_line()			read and process a line
#
#
# Configuration:
#       -none-
#
###
### Constants (do NOT try to change them)
###
#
# Definition of package
#
package BWF;
 require Exporter;
 our @ISA =             qw(Exporter);
 our @EXPORT_OK =       qw(debug
                           parse_log_line
                        );
#
# Force strict mode
#
use strict;
#
###
### Local variables
###
#
# Debugging flag
#
my $debug = 0;
#
##
## BWF::parse_log_line()
##  function to grab the line with optionally creating a new message hash
##
sub parse_log_line
 { my $procedureName = 'BWF::parse_log_line';
   #
   # Called with message store by reference
   #
   my($messageStoreReference,$line,$funcReference) = @_;
   #
   # Grab the line we were given and create a new message hash for our message
   #
   my %message = ();
   #
   # These are the components we may have parsed out of the message based on the service
   #
   my ($_epochTime,$_srcIP,$_destIP,$_contentType,$_srcIP2,$_destURL,$_dataSize,$_md5Anchor,$_action,$_reason,$_formatVersion,$_matchFlag,$_TQflag,$_actionType,$_srcType,$_srcDetail,$_destType,$_destDetail,$_spyType,$_spyId,$_infectionScore,$_matchedPart,$_matchedCategory,$_userInfo,$_refererDomain,$_refererCategory,$_WSA);
   #
   # SAMPLE log line....
   #
   # May 12 09:14:06 proxyads http_scan[46658]: 1431414846 1 193.196.79.177 80.156.249.61 application/x-fcs 193.196.79.177 http://80.156.249.61/idle/276mdz02wSLVyg8Z/392 284
   #     BYF ALLOWED CLEAN  2 1 1 0 4 (-) 0 - 0 - 0 80.156.249.61 - [zuas8462]  http://watch.nba.com/nba/video/channels/tnt_overtime/2015/04/24/ watch.nba.com sports 0
   #
   # Matching expressions (numbered):
   #                            1             2          3          4          5          6          7          8          9                             10                      11         12         13      14       15         16         17        18        19         20         21         22          23        24         25          (26)
   if ($line =~ /scan\[\d+\]:\s+(\d+)\s+\d+\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(ALLOWED|BLOCKED|DETECTED)\s+(CLEAN|VIRUS|SPYWARE)\s+([\d]+)\s+([\d])\s+([\d]+)\s+([\d]+)\s+([\d]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(.*)$/)
      {
	#
	# Grab the main pieces of the log entry and the process specific info
	# 1           2       3        4             5        6         7          8           9        10       11              12          13       14        15          16         17          18         19     20                21           22                  23         24             25                 26
	#
	($_epochTime,$_srcIP,$_destIP,$_contentType,$_srcIP2,$_destURL,$_dataSize,$_md5Anchor,$_action,$_reason,$_formatVersion,$_matchFlag,$_TQflag,$_actionType,$_srcType,$_srcDetail,$_destType,$_destDetail,$_spyType,$_spyId,$_infectionScore,$_matchedPart,$_matchedCategory,$_userInfo,$_refererDomain,$_refererCategory,$_WSA)=
	($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26);
	#
	#
	#
	$message{epochTime} =	$_epochTime;
	$message{srcIP} =	$_srcIP;
	$message{destIP} =	$_destIP;
	$message{contentType} =	$_contentType;
	$message{srcIP2} =	$_srcIP2;
	$message{destURL} =	$_destURL;
	$message{dataSize} =	$_dataSize;
	$message{md5Anchor} =	$_md5Anchor;
	$message{action} =	$_action;
	$message{reason} =	$_reason;
	$message{formatVersion}=$_formatVersion;
	$message{matchFlag} =	$_matchFlag;
	$message{TQflag} =	$_TQflag;
	$message{actionType} =	$_actionType;
	$message{srcType} =	$_srcType;
	$message{srcDetail} =	$_srcDetail;
	$message{destType} =	$_destType;
	$message{destDetail} =	$_destDetail;
	$message{spyType} =	$_spyType;
	$message{spyId} =	$_spyId;
	$message{infectionScore}=$_infectionScore;
	$message{matchedPart} =	$_matchedPart;
	$message{matchedCategory}=$_matchedCategory;
	$message{userInfo} =	$_userInfo;
	$message{refererDomain}=$_refererDomain;
	$message{refererCategory}=$_refererCategory;
	$message{WSA} =		$_WSA;
	#
	# Print everything for debugging
	#
	if ($debug)
	   { print STDERR "${procedureName}(): full debugging output of read syslog line:\n" if ($debug > 9);
	     print STDERR $_;
	     for my $item (keys(%message))
	      { print STDERR pretty($item).$message{$item}."\n";  }
	     print STDERR "\n";
	    }
	#
	# Print everything for debugging
	#
	my $flagSkipThisItem = 0;
	if (defined($funcReference))
	   { #
	     # Call the discriminator function with all informations
	     #  awaiting as result 1 to skip this entry
	     #
	     $flagSkipThisItem = $funcReference->(\%message);
	     print STDERR "${procedureName}(): discriminator function returned $flagSkipThisItem.\n" if ($debug > 1);
	   }
	#
	# Put a ref to this message onto our array of messages so we can use it later
	#
	push(@$messageStoreReference, \%message) if (!$flagSkipThisItem);
	#
	# Send back whatever info you would like to the caller here. In this case
	# we are sending back the end time as an example that could handle tracking
	# last seen message time or something similar
	#
        print STDERR "${procedureName}(): returning a timestamp as line does match expected syntax.\n" if ($debug > 1);
	return( $_epochTime );
      }
   #
   # No message info to send back
   #
   print STDERR "${procedureName}(): returning (undef) as line does not match expected syntax.\n" if ($debug > 1);
   return undef;
  }

###
### Start of main script
###
#
# Terminate with success
#
1;
#
# Vim autoconfiguration (Modelines) line follows...
# vi:set noai:shiftwidth=1:
#
# end-of-BWF.pm
#
