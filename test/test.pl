#!/usr/bin/perl
######################################################################
# test.pl                                                 October 1999
# Horms                                             horms@verge.net.au
#
# Test suite for perditon mail retrival proxy
#
# See usage subroutine for usage information.
#
# perdition
# Mail retrieval proxy server
# Copyright (C) 1999-2004  Horms
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
# 02111-1307  USA
#
######################################################################

use strict;
use IO::Socket;

my $DEFAULT_PORT="110";
my $STDIN_HOST="-";
my $DEFAULT_HOST="$STDIN_HOST";

my $POP3_PROTOCOL_STRING=["^\\\+OK", "^-ERR", "^-ERR"];
my $POP3_UNTAGGED="^NULL\$";
my $POP3_CONT="^S: ";
my $IMAP4_PROTOCOL_STRING=["^\\\S+ OK", "^\\\S+ NO", "^\\\S+ BAD"];
my $IMAP4_UNTAGGED="^\\\* ";
my $IMAP4_CONT="^\\\+ ";

{ #Denise's main
  my (
    $host, 
    $port, 
    $client_in, 
    $client_out, 
    $filename, 
    $tests,
    $test_string,
    $expected_result,
    $succede,
    $fail,
    $date,
    $protocol,
    $protocol_string,
    $untagged,
    $cont,
  );

  unless($protocol = $ARGV[0]){ &usage(); }
  if($protocol=~/^imap4$/i){
    $protocol_string=$IMAP4_PROTOCOL_STRING;
    $untagged=$IMAP4_UNTAGGED;
    $cont=$IMAP4_CONT;
  }
  elsif($protocol=~/^pop3$/i){
    $protocol_string=$POP3_PROTOCOL_STRING;
    $untagged=$POP3_UNTAGGED;
    $cont=$POP3_CONT;
  }
  else{
    &usage();
  }
  unless($filename = $ARGV[1]){ &usage(); }
  unless($host = $ARGV[2]){ $host=$DEFAULT_HOST;}
  unless($port = $ARGV[3]){ $port=$DEFAULT_PORT;}

  $date=localtime;
  
  print <<__EOF__;
Test Parameters
===============
Date:     $date
Protocol: $protocol                      
Filename: $filename                      
Host:     $host                      
Port:     $port

Test Results
============
__EOF__

  $tests=&read_test_file($filename);
  if($tests==-1){
    exit(-1);
  }

  $succede=0;
  $fail=0;
  $client_in = -1;
  $client_out = -1;
  foreach (@$tests){
    if(@$_[1] eq "NULL") {
      if($client_in >= 0) {
        close($client_in);
      }
      if($client_out >= 0) {
        close($client_out);
      }
      if("$host" eq "$STDIN_HOST"){
        ($client_in, $client_out)=&stdio_handle(); 
      }
      else {
        $client_in = $client_out = &client_socket_open($host, $port);
      }
    }

    if((&do_test(
      $client_in,
      $client_out,
      @$_[1],
      @$_[0],
      1,
      $protocol_string,
      $untagged,
      $cont
    ))==1){
      $succede++;
    }
    else {
      $fail++;
    }
  }

  print <<__EOF__;
Summary
=======
Succede: $succede
Fail:    $fail
__EOF__

}


######################################################################
# Usage subroutine
######################################################################

sub usage () {
  my ($status)=(@_);

  if($status ne 0){
    *STDOUT = *STDERR;
  }

  print <<__EOF__;
Usage: test.pl [imap4|pop3] input_filename [host] [port]
  input_filename: file to read tests from
  host: host to connect to. - for stdio. (default $DEFAULT_HOST).
  port: port to connect to. Not used when in stdio mode. 
        (default $DEFAULT_PORT).
__EOF__

  exit($status);
}


######################################################################
# client_socket_open
# Open a socket connection for listening
# pre: host: host to connect to
#      port: port to connect to
# return: IO::Socket for client
#         exits on error.
######################################################################

sub client_socket_open {
  my ($host, $port)=(@_);

  my $socket = IO::Socket::INET->new(
    'PeerAddr' => $host,
    'PeerPort' => $port,
    'Proto'    => "tcp",
    'Type'     => SOCK_STREAM
  ) or &show_error("Couldn't connect to $host\n");

  return($socket);
}


######################################################################
# stdio_handle
# Create a IO::Handle for stdio
# Code mostly from IO::Handle(3)
# pre: none
# return: Array with two IO::Handles, first element is for stdin and
#         the second element is for stdout
#         Empty array on error
###################################################################### 

sub stdio_handle {
   my $stdin = new IO::Handle;
   unless ($stdin->fdopen(fileno(STDIN),"r")) {
     &show_error("stdio_handle: \$stdin->fdopen");
     return ();
   }

   my $stdout = new IO::Handle;
   unless ($stdout->fdopen(fileno(STDOUT),"w")) {
     &show_error("stdio_handle: \$stdout->fdopen");
     return ();
   }

   return ($stdin, $stdout);
}


######################################################################
# show_error
# Show an error message, a poor persons perror.
# pre: String to show in error
######################################################################

sub show_error {
  my ($string)=(@_);

  chomp $string;

  print STDERR "$string: $!\n";
}


######################################################################
# read_response
# Read the response from a server
# pre: fh: IO::Handle to read from
#      verbose: if set to 1 data read from server will be displayed
#      protocol_string: Strings to expect from the server
#                       An referance to an array. element 
#                               0 is positive response, 
#                               1 is negative response,
#                               2 is error response
#                       Strings are perl regular expressions
#      untagged: lines matching this regex are skipped
#      cont lines matching this regex are skipped
# post: index of element of array found as first white space
#       delimited token
#       -1 if token is not found
#
# Note: the protocol_strings array is seached in order, hence, the
# first index will be returned if a string appears multiple times
# in the array.
######################################################################

sub read_response {
  my ($fh, $verbose, $protocol_string, $untagged, $cont)=(@_);
  
  my($line, $i);

  while(1){
    $line=$fh->getline;
    if($verbose==1){
      print "<$line";
    }

    if($line=~/$cont/) {
      next;
    }
  
    $i=0;
    foreach (@$protocol_string){
      if($line=~/$_/){
        return($i);
      }
      $i++;
    }

    unless($line=~/$untagged/) {
       last;
    }
  }

  return(-1);
}  


######################################################################
# do_test
# Test the response to some input
# pre: in_fh:   IO::Handle to read from
#      out_fh:  IO::Handle to read to
#      input:   "NULL" means no input
#      expected_response: Expected response as returned by read_response
#      verbose: if set to 1 the results are printed to STDOUT
#               else no results are displayed
#      protocol_string: protocol strings to be passwd to read_response
#      untagged: Lines that match this regex are skipped
#      cont: Lines that match this regex are skipped
# post: 1 if response matches expected_response
#       0 if response does not match expected response
######################################################################

sub do_test {
  my (
    $in_fh, 
    $out_fh, 
    $input, 
    $expected_response, 
    $verbose, 
    $protocol_string,
    $untagged,
    $cont
  )=(@_);

  my ($response, $status, $status_string);

  if($input ne "NULL"){
    local $/='\n';
    unless($input =~ m/\r\n$/) {
      $input .= "\r\n";
    }
    $out_fh->print("$input");
    if($verbose==1){
      print ">$input";
    }
  }

  $response=&read_response($in_fh, $verbose, $protocol_string, $untagged,
  	$cont);
  if($expected_response>0){
     sleep 10;
  }
  $status=($response==$expected_response)?1:0;

  if($verbose==1){
    my $status_string=($status==1)?"Success":"Failed";
print <<__EOF__;
Test:              "$input"
Expected Response: $expected_response ($$protocol_string[$expected_response])
Response:          $response ($$protocol_string[$response])
Status:            $status_string

__EOF__
  }

  return($status);
}


######################################################################
# read_test_file
# pre: filename: input filename
#      input in the following form:
#      The first whitespace delimited field is the expected
#      response as per the responses from get_response. The rest
#      of the line is the test string 
#      e.g.: "0 user flim"
# post: referance to a two dimentional array 
#       ( (expected_response, "test string") ... )
#       -1 on error
######################################################################

sub read_test_file {
  my ($filename)=(@_);

  my (@result);

  unless(open FLIM, "<$filename"){
    show_error "read_test_file: open";
    return -1;
  }

  while(<FLIM>){
    my $one;
    my $two;
    next if(/^#/);
    /^(\S*)\s(.*)/;
    $one = $1;
    $two = $2;
    $one =~ s/\\r\\n/\r\n/g;
    $two =~ s/\\r\\n/\r\n/g;
    push @result, [$one, $two];
  }

  return \@result;
}    
