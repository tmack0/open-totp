#!/usr/bin/perl
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright 2002  The FreeRADIUS server project
#  Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#  
#  TOTP Edits
#  Copyright 2013  Evernote
#  Copyright 2013  Theral Mackey <tmackey@evernote.com>
#
 
#
# TOTP for use with rlm_perl
# This script will validate TOTP codes for users from secrets stored i(encrypted) in LDAP.
# It assumes the usernames presented from radius are matched to the user's uid in LDAP.
# It can do both 2-factor with TOTP and LDAP password checking, or just TOTP (read the comments).
# The Ldap-UserDn attribute is used to perform the user ldap bind. This attr is created in freeradius
#  configs with a line like DEFAULT Ldap-UserDn := uid=%{User-Name},ou=people,dc=company,dc=com
#  use that or generate it from the User-Name attr in this script if needed.

use strict;
# use ...
# This is very important ! Without this script will not get the filled  hashesh from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);
##use Data::Dumper;
use Net::LDAP;
use Authen::OATH;
use MIME::Base64;
use Crypt::CBC;
use Digest::MD5;

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;
 
my $LDAPSERVER = 'ldaps://127.0.0.1';
my $LDBASE = 'ou=people,dc=example,dc=com';
my $OTPDIGITS = 6;
my $OTPSTEP = 60;
my $TOTP_ATTR = 'description';
my $TOTP_BIND_USER = 'cn=totpauthenticator,dc=example,dc=com';
my $TOTP_BIND_PASS = "BindPassword or read it from a mode 400 file";
my $TOTP_KEY = "TOTP Secret encryption key, or as above, read it from a file";
my $OTP_PATH = '/tmp/totp';

chomp($TOTP_BIND_PASS);
chomp($TOTP_KEY);
#
# This the remapping of return values
#
  use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
  use constant    RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
  use constant    RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
  use constant    RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
  use constant    RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
  use constant    RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
  use constant    RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
  use constant    RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
  use constant    RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
  use constant    RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */
   
# Function to handle authorize
sub authorize {
    # For debugging purposes only
    #       &log_request_attributes;
    
    # Here's where your authorization code comes
    # You can call another function from here:
    &test_call;
    
    return RLM_MODULE_OK;
}

### Note that the RAD_REPLY{'Reply-Message'} string is returned to FreeRADIUS for any result.
### Be careful what they contain. DEBUG ones are included but commented out here, and might be set to return sensitive data
### These messages are returned to the NAS and potentially the end user! USE ONLY FOR DEBUG and sanitize before actual use!!!
 
# Function to handle authenticate
sub authenticate {
        
    $RAD_REPLY{'Reply-Message'} = "Authentication Failed!\n";
    my ($otp,$ldpass) = $RAD_REQUEST{'User-Password'} =~ /^(\d{$OTPDIGITS})(.{0,256})/;
    ##$RAD_REPLY{'Reply-Message'} = "Pre OTP Digits check: $otp\n";
    return RLM_MODULE_INVALID unless($otp =~ /^\d{$OTPDIGITS}/);
    
    ### If you want to use TOTP by itself (ie: no ldap authorization check in here) comment out the following section
    # First, strip what should be the TOTP code from the supplied password
    my $ldaph = Net::LDAP->new($LDAPSERVER) or return RLM_MODULE_FAIL;
    ##$RAD_REPLY{'Reply-Message'} = "Pre ldap bind: $ldpass, $RAD_CHECK{'Ldap-UserDn'}";
    # Perform a bind with the User's DN and supplied password, reject if this fails.
    my $bindcheck = $ldaph->bind($RAD_CHECK{'Ldap-UserDn'}, password => $ldpass);
    ##$RAD_REPLY{'Reply-Message'} = "Post ldap bind: ".$bindcheck->code." $ldpass, $RAD_CHECK{'Ldap-UserDn'} . ".join(',',keys(%RAD_REQUEST));
    $ldaph->unbind(); # close the bind, TOTP needs a special user.
    return RLM_MODULE_REJECT if($bindcheck->code);
    ###
 
    ## This section handles the TOTP code
    $ldaph = Net::LDAP->new($LDAPSERVER) or return RLM_MODULE_FAIL;
    $bindcheck = $ldaph->bind($TOTP_BIND_USER, password => $TOTP_BIND_PASS);
    ##$RAD_REPLY{'Reply-Message'} = 'LDAP Bind failed! Cheeck servers/bind creds! '.$bindcheck->code;
    return RLM_MODULE_REJECT if($bindcheck->code);
    my $ldapq = $ldaph->search(base => $LDBASE, scope=> 'sub', filter => 'uid='.$RAD_REQUEST{'User-Name'}, attrs => [$TOTP_ATTR]);
    my $ldaptotp = 'INVALID';
    if($ldapq->entry(0)){
      $ldaptotp = $ldapq->entry(0)->get_value($TOTP_ATTR);
    }
    else{
	##$RAD_REPLY{'Reply-Message'} = 'LDAP user not found! '.$RAD_REQUEST{'User-Name'};
	return(RLM_MODULE_REJECT);
    }
    if($ldaptotp eq 'INVALID'){
	##$RAD_REPLY{'Reply-Message'} = 'LDAP user has no TOTP secret! '.$RAD_REQUEST{'User-Name'}.'-'.$ldaptotp;
	return(RLM_MODULE_REJECT);
    }
    ## Setup the stored hash for decryption
    $ldaptotp =~ /^(.{8})(.*)$/;
    my $totp_iv = $1;
    my $ldtotp_sec = $2;
    unless(($ldtotp_sec =~ /\w/) && ($totp_iv =~ /\w/)){
	##$RAD_REPLY{'Reply-Message'} = 'LDAP user has bad TOTP secret! '.$RAD_REQUEST{'User-Name'}.'-'.$totp_iv.'-'.$ldtotp_sec;
	return(RLM_MODULE_REJECT);
    }
    my $crypth =  Crypt::CBC->new( {'key' => $TOTP_KEY, 'cipher' => "Blowfish", 'iv' => $totp_iv, 'literal_key' => 1, 'header' => 0, 'padding' => 'null', 'prepend_iv' => 0 } );
    # base64 decode the crypt and decrypt it
    ##$RAD_REPLY{'Reply-Message'} = 'LDAP user has bad TOTP secret! '.$RAD_REQUEST{'User-Name'}.'-'.$totp_iv.'-'.$ldtotp_sec;
    $ldtotp_sec = $crypth->decrypt(decode_base64($ldtotp_sec)) || return(RLM_MODULE_REJECT);
    
    # Perform the TOTP calculation and compare codes
    my $oath = Authen::OATH->new("digits" => $OTPDIGITS, "timestep" => $OTPSTEP);
    chomp($ldtotp_sec);
    my $totp = $oath->totp($ldtotp_sec);
    # $RAD_REPLY{'Reply-Message'} = "TOTP Verification failed! IV $totp_iv $ldtotp_sec $totp ". time;
    return RLM_MODULE_REJECT unless($totp =~ /^\d{$OTPDIGITS}$/);
    if($totp == $otp){
	
	#########################
    ##  Single-use code check, $OTP_PATH must exist, and be writable by the freerad user.
	##  To save on run time you can comment this out, but that will reduce security slightly 
	##  as it would allow reuse of codes on this server. Note that it does not prevent other
	##  servers from accepting a code on this server unless the $OTP_PATH dir is kept in sync
	#########################
	my $md5h = Digest::MD5->new;
	$md5h->add($RAD_REQUEST{'User-Name'}.$totp_iv.$totp);
	my $md5name = $md5h->hexdigest;
	my $totpfname = $OTP_PATH.'/'.$md5name;
	my $ctime = 0;
	if( -e $totpfname){
	    $ctime = (stat($totpfname))[9];
	    ## $RAD_REPLY{'Reply-Message'} = "Code $totp checking $OTPSTEP seconds: ".(time() - $ctime)." for user $RAD_REQUEST{'User-Name'}! in $totpfname";
	    if(time() - $ctime < $OTPSTEP){
                ## $RAD_REPLY{'Reply-Message'} = "Code $totp has already been used within $OTPSTEP seconds for user $RAD_REQUEST{'User-Name'}! ". time;
		return RLM_MODULE_REJECT;
	    }
	    else{
		unlink($totpfname);
	    }
	}
	opendir(OTPDIR, $OTP_PATH);
	## Cleanup stale codes
	foreach my $f(readdir(OTPDIR)){
	    next if($f !~ /^[a-f0-9]+$/);
	    my $nctime = (stat($f))[9];
	    if(time() - $nctime > $OTPSTEP){
		## $RAD_REPLY{'Reply-Message'} = "Code $totp unlinking ".$OTP_PATH.'/'.$f." for $ctime being $OTPSTEP + more than ".time();
		unlink($OTP_PATH.'/'.$f);
	    }
	}
	closedir(OTPDIR);
	open(OTPCHECK,'>',$totpfname);
	close(OTPCHECK);
	chmod(0600,$totpfname);
	############################

	delete($RAD_REPLY{'Reply-Message'});
	return RLM_MODULE_OK;
    }
}
 
# Function to handle preacct
sub preacct {
        # For debugging purposes only
    #       &log_request_attributes;
     
        return RLM_MODULE_OK;
    }
 
# Function to handle accounting
sub accounting {
        # For debugging purposes only
    #       &log_request_attributes;
     
        # You can call another subroutine from here
        &test_call;
     
        return RLM_MODULE_OK;
    }
 
# Function to handle checksimul
sub checksimul {
        # For debugging purposes only
    #       &log_request_attributes;
     
        return RLM_MODULE_OK;
    }
 
# Function to handle pre_proxy
sub pre_proxy {
        # For debugging purposes only
    #       &log_request_attributes;
     
        return RLM_MODULE_OK;
    }
 
# Function to handle post_proxy
sub post_proxy {
        # For debugging purposes only
    #       &log_request_attributes;
     
        return RLM_MODULE_OK;
    }
 
# Function to handle post_auth
sub post_auth {
        # For debugging purposes only
    #       &log_request_attributes;
     
        return RLM_MODULE_OK;
    }
 
# Function to handle xlat
sub xlat {
        # For debugging purposes only
    #       &log_request_attributes;
     
        # Loads some external perl and evaluate it
        my ($filename,$a,$b,$c,$d) = @_;
        &radiusd::radlog(1, "From xlat $filename ");
        &radiusd::radlog(1,"From xlat $a $b $c $d ");
        local *FH;
        open FH, $filename or die "open '$filename' $!";
        local($/) = undef;
        my $sub = <FH>;
        close FH;
        my $eval = qq{ sub handler{ $sub;} };
        eval $eval;
        eval {main->handler;};
    }
 
# Function to handle detach
sub detach {
        # For debugging purposes only
    #       &log_request_attributes;
     
        # Do some logging.
        &radiusd::radlog(0,"rlm_perl::Detaching. Reloading. Done.");
    }
 
 
sub test_call {
    # Some code goes here
}
 
sub log_request_attributes {
        # This shouldn't be done in production environments!
        # This is only meant for debugging!
    for (keys %RAD_REQUEST) {
    &radiusd::radlog(1, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
    }
}
