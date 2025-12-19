<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>${HOSTNAME}</hostname>
    <domain>${DOMAIN}</domain>
    <timezone>${TIMEZONE}</timezone>

    <ssh>
      <enable>1</enable>
    </ssh>

    <user>
      <name>root</name>
      <password>${ROOT_PASSWORD_HASH}</password>
      <uid>0</uid>
      <scope>system</scope>
    </user>
  </system>

  <interfaces>
    <wan>
      <enable>1</enable>
      <if>${WAN_IF}</if>
      ${WAN_IP_BLOCK}
    </wan>

    <lan>
      <enable>1</enable>
      <if>vtnet1</if>
      <ipaddr>192.168.10.1</ipaddr>
      <subnet>24</subnet>
    </lan>
  </interfaces>

  ${WAN_GATEWAY_BLOCK}
</opnsense>
