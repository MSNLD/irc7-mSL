on ^*:LOGON:*:{
  ; Identify as MSN-OCX v9.02.0310.2401 (final version)
  raw -qn IRCVERS IRC8 MSN-OCX!9.02.0310.2401 en-us
  ; GateKeeper v3, Sequence 1
  raw -qn AUTH GateKeeper I $+(:GKSSP\0JD,$chr(3),\0\0\0,$chr(1),\0\0\0)
  haltdef
}

on *:PARSELINE:in:*:{
  tokenize 32 $iif($rawbytes, $ifmatch, $parseline)
  if ($1 == AUTH) {
    if ($3 == *) {
      if ($2 == GateKeeper) {
        raw -qn USER $iif($gettok($email, 1, 64), $ifmatch, $me) 0 * : $+ $iif($fullname, $ifmatch, ...)
        raw -qn NICK > $+ $remove($me, >)
      }
    }
    ; This should never happen as we're not sending GateKeeperPassport
    elseif ($3- == S :OK) {
      raw -qn $1-3 $+($base($len(%ticket),10,16,8),%ticket,$base($len(%profile),10,16,8),%profile)
      PROP $ MSNREGCOOKIE : $+ %cookie
      PROP $ MSNPROFILE :0
      PROP $ SUBSCRIBERINFO : $+ %subinfo
    }
    else {
      if ($regex($1-, /^AUTH\sGateKeeper(?:Passport)?\sS\s:GKSSP\\0(?:[^\\]|\\.){2}\x03\\0\\0\\0\x02\\0\\0\\0([^\\]|\\.)([^\\]|\\.)([^\\]|\\.)([^\\]|\\.)([^\\]|\\.)([^\\]|\\.)([^\\]|\\.)([^\\]|\\.)$/u)) {
        ; Create an 8 byte binary variable
        bset &challenge $regml(0) 0
        var %i = 1
        while (%i <= $regml(0)) {
          ; Add challenge bytes to bvar after unescaping
          bset -a &challenge %i $iif($left($regml(%i),1) != \,$asc($v1),$replace($right($regml(%i),1),t,9,n,10,r,13,b,32,c,44,\,92))
          inc %i
        }
        ; Add hostname to the end of bvar (applies only to GateKeeper v3)
        bset -at &challenge $calc($regml(0) + 1) $servertarget
        ; Send our reply.
        raw -qn $1-3 $+(:GKSSP\0\0\0,$chr(3),\0\0\0,$chr(3),\0\0\0,$regsubex($remove($hmac(&challenge,SRFMKSJANDRESKKC,md5,1),$chr(32)),/([0-9A-Fa-f]{2})/g,$iif(\1 isin 00 0A 0D 2C 09 5C 20,\ $+ $replacex(\1,00,0,0A,n,0D,r,2C,c,09,t,5C,\,20,b),$chr($base(\1,16,10)))))
        ; TODO: Parseline -obqn (-u)
      }
    }
  }
  elseif ($2 == JOIN) {
    ; Remove profile data so mIRC/AdiIRC can understand the join
    .parseline -it $1-2 $4-
  }
  elseif ($2 == PRIVMSG) {
    ; TODO: Remove font information
  }
  elseif ($2 == WHISPER) {
    ; TODO: Remove font information
  }
  elseif ($2 == 004) {
    ; This is specifically for mIRC - Allows user to join channels with %# prefix.
    .parseline -itq : $+ $server 005 $me PREFIX=(qov).@+ CHANTYPES=%#
  }
  elseif ($2 == 353) {
    ; Removes profile information from 353 (RPL_NAMES)
    if ($chr(44) isin $6) {
      var %onames = $right($6-, -1)
      var %i = 1
      var %names
      while (%i <= $numtok(%onames, 32)) {
        var %name = $gettok(%onames, %i, 32)
        var %profile = $gettok(%name, 1-3, 44)
        var %target = $gettok(%name, 4, 44)
        %names = %names %target
        signal MSNPROFILE $5 $remove(%target, ., @, +) %profile
        inc %i
      }
      .parseline -it $1-5 $+(:, %names)
      return
    }
  }
}

; Client specific variables are currently unused.

alias -l getClientName return $iif(!$~adiircexe, mIRC, AdiIRC)

alias getSupportedClient {
  var %supported = $false
  if ($getClientName == AdiIRC) {
    ; AdiIRC
    if ($version < 4.4) {
      echo $color(info) -at * You're on an unsupported version of AdiIRC. Please use AdiIRC v4.4 or later.
    }
    elseif ($beta < 20230614) {
      echo $color(info) -at * You're on an unsupported beta of AdiIRC. Please use AdiIRC beta 20230614 or later.
    }
    else {
      %supported = $true
    }
  }
  else {
    ; TODO: Check mIRC minimum requirements. Probably where $hmac or /parseline was added.
  }
}

;-- IRC7 Self Updater

on *:LOAD:{
  irc7.update
}

;--- Startup
on *:START:{
  irc7.update
}

alias irc7.update {
  sockclose irc7.update
  var %d = irc7.update raw.githubusercontent.com
  sockopen $iif($sslready, -e %d 443, %d 80)
  echo $color(info) -st * Checking for irc7 updates...
}

on 1:sockopen:irc7.update:{
  if ($sockerr > 0) {
    echo $color(info) -st * irc7 update failed (Connection error)
    return
  }
  write -c $qt($scriptdirtmp.bin)
  sockwrite $sockname GET /MSNLD/irc7-mSL/main/irc7.mrc HTTP/1.0 $+ $crlf
  sockwrite $sockname HOST: raw.githubusercontent.com $+ $crlf $+ $crlf
}

on 1:sockread:irc7.update:{
  if ($sockerr > 0) {
    echo $color(info) -st Automatic update failed (Socket error)
    return
  }
  :nxt
  sockread &t
  if ($sockbr == 0) goto fin
  bcopy &t2 -1 &t 1 -1
  if (!$sock($sockname).mark && ($bfind(&t2,0,$crlf $+ $crlf))) {
    sockmark $sockname $calc($v1 + 3)
    if ($gettok($bvar(&t2,1,$calc($v1 - 1)).text,2,32) !== 200) {
      echo $color(info) -st * irc7 update failed (Unexpected HTTP Status Code)
      sockclose $sockname
      return
    }
  }
  goto nxt
  :fin
  if ($sock($sockname).mark > -1) {
    bcopy &t3 1 &t2 $calc($v1 + 1) $calc($bvar(&t2,0) - $v1)
    bwrite $qt($scriptdirtmp.bin) -1 -1 &t3
    sockmark $sockname 0
  }
  else {
    echo $color(info) -st * irc7 update failed (Parser error)
    sockclose $sockname
  }
}

on 1:sockclose:irc7.update:{
  if ($sockerr > 0) echo $color(info) -st * Automatic update failed (Socket Error)
  else {
    if ($md5($scriptdirtmp.bin,2) === $md5($script,2)) echo $color(info) * No new updates found
    else {
      var %fn $qt($scriptdirirc7.mrc)
      echo $color(info) -st * New update successfully installed!
      .rename -fo $qt($scriptdirtmp.bin) %fn
      .load -rs %fn
      if ($qt($script) != %fn) {
        .remove $qt($script)
        .unload -rs $qt($script)
      }
    }
  }
}
