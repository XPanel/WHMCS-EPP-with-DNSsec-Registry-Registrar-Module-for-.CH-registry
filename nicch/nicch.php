<?php
/**
*
* NOTICE OF LICENSE
*
*  @package   NICCH
*  @version   1.0.1
*  @author    Lilian Rudenco <info@xpanel.com>
*  @copyright 2019 Lilian Rudenco
*  @link      http://www.xpanel.com/
*  @license   http://opensource.org/licenses/afl-3.0.php  Academic Free License (AFL 3.0)
*/

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\Schema\Blueprint;

function nicch_MetaData()
{
    return array(
        'DisplayName' => 'NIC.CH EPP Module for WHMCS',
        'APIVersion' => '1.0.1',
    );
}

function _nicch_error_handler($errno, $errstr, $errfile, $errline)
{
	if (!preg_match("/nicch/i", $errfile)) {
		return true;
	}

	_nicch_log("Error $errno:", "$errstr on line $errline in file $errfile");
}

set_error_handler('_nicch_error_handler');
_nicch_log('================= ' . date("Y-m-d H:i:s") . ' =================');

function nicch_getConfigArray($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	_nicch_create_table();
	_nicch_create_column();

	$cafiles = array();
	$d = dir(__DIR__ . '/cafile');
	while (false !== ($entry = $d->read())) {
		if (preg_match("/^\./i", $entry)) {
			continue;
		}

		$cafiles[] = $entry;
	}

	$local_certs = array();
	$d = dir(__DIR__ . '/local_cert');
	while (false !== ($entry = $d->read())) {
		if (preg_match("/^\./i", $entry)) {
			continue;
		}

		$local_certs[] = $entry;
	}

	$local_pkeys = array();
	$d = dir(__DIR__ . '/local_pk');
	while (false !== ($entry = $d->read())) {
		if (preg_match("/^\./i", $entry)) {
			continue;
		}

		$local_pkeys[] = $entry;
	}

	$configarray = array(
		'FriendlyName' => array(
			'Type' => 'System',
			'Value' => 'NICCH',
		),
		'Description' => array(
			'Type' => 'System',
			'Value' => 'This module can be used with .CH registry',
		),
		'host' => array(
			'FriendlyName' => 'EPP Server',
			'Type' => 'text',
			'Size' => '32',
			'Default' => 'epp-test.switch.ch',
			'Description' => 'EPP Server Host.'
		),
		'port' => array(
			'FriendlyName' => 'Server Port',
			'Type' => 'text',
			'Size' => '4',
			'Default' => '700',
			'Description' => 'System port number 700 has been assigned by the IANA for mapping EPP onto TCP.'
		),
		'verify_peer' => array(
			'FriendlyName' => 'Verify Peer',
			'Type' => 'yesno',
			'Description' => 'Require verification of SSL certificate used.'
		),
		'cafile' => array(
			'FriendlyName' => 'CA File',
			'Type' => 'dropdown',
			'Options' => implode(',', $cafiles),
			'Description' => 'Certificate Authority file which should be used with the verify_peer context option <br />to authenticate the identity of the remote peer.'
		),
		'local_cert' => array(
			'FriendlyName' => 'Certificate',
			'Type' => 'dropdown',
			'Options' => implode(',', $local_certs),
			'Description' => 'Local certificate file. It must be a PEM encoded file.'
		),
		'local_pk' => array(
			'FriendlyName' => 'Private Key',
			'Type' => 'dropdown',
			'Options' => implode(',', $local_pkeys),
			'Description' => 'Private Key.'
		),
		'passphrase' => array(
			'FriendlyName' => 'Pass Phrase',
			'Type' => 'text',
			'Size' => '32',
			'Description' => 'Enter pass phrase with which your certificate file was encoded.'
		),
		'clid' => array(
			'FriendlyName' => 'Client ID',
			'Type' => 'text',
			'Size' => '20',
			'Description' => 'Client identifier.'
		),
		'pw' => array(
			'FriendlyName' => 'Password',
			'Type' => 'password',
			'Size' => '20',
			'Description' => "Client's plain text password."
		),
		'registrarprefix' => array(
			'FriendlyName' => 'Registrar Prefix',
			'Type' => 'text',
			'Size' => '4',
			'Description' => 'Registry assigns each registrar a unique prefix with which that registrar must create contact IDs.'
		)
	);
	return $configarray;
}

function _nicch_startEppClient($params = array())
{
	$s = new nicch_epp_client($params);
	$s->login($params['clid'], $params['pw'], $params['registrarprefix']);
	return $s;
}

function nicch_RegisterDomain($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-check-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<check>
	  <domain:check
		xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
		xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:check>
	</check>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->chkData;
		$reason = (string)$r->cd[0]->reason;
		if (!$reason) {
			$reason = 'Domain is not available';
		}

		if (0 == (int)$r->cd[0]->name->attributes()->avail) {
			throw new exception($r->cd[0]->name . ' ' . $reason);
		}

		$contacts = array();
		foreach(array(
			'registrant',
			'tech'
		) as $i => $contactType) {
			$from = $to = array();
			$from[] = '/{{ id }}/';
			$id = strtoupper($params['registrarprefix'] . '' . $contactType . '' . $params['domainid']);
			$to[] = htmlspecialchars($id);
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-check-' . $clTRID); // vezi la create tot acest id sa fie
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<check>
	  <contact:check
		xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"
		xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
		<contact:id>{{ id }}</contact:id>
	  </contact:check>
	</check>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->chkData;

			//		$reason = (string)$r->cd[0]->reason;
			//		if (!$reason) {
			//			$reason = 'Contact is not available';
			//		}

			if (1 == (int) $r->cd[0]->id->attributes()->avail) {

				// contact:create

				$from = $to = array();
				$from[] = '/{{ id }}/';
				$id = strtoupper($params['registrarprefix'] . '' . $contactType . '' . $params['domainid']); // vezi la check tot acest id sa fie
				$to[] = htmlspecialchars($id);
				$from[] = '/{{ name }}/';
				$to[] = htmlspecialchars($params['firstname'] . ' ' . $params['lastname']);
				$from[] = '/{{ org }}/';
				$to[] = htmlspecialchars($params['companyname']);
				$from[] = '/{{ street1 }}/';
				$to[] = htmlspecialchars($params['address1']);
				$from[] = '/{{ street2 }}/';
				$to[] = htmlspecialchars($params['address2']);
				$from[] = '/{{ street3 }}/';
				$street3 = (isset($params['address3']) ? $params['address3'] : '');
				$to[] = htmlspecialchars($street3);
				$from[] = '/{{ city }}/';
				$to[] = htmlspecialchars($params['city']);
				$from[] = '/{{ state }}/';
				$to[] = htmlspecialchars($params['state']);
				$from[] = '/{{ postcode }}/';
				$to[] = htmlspecialchars($params['postcode']);
				$from[] = '/{{ country }}/';
				$to[] = htmlspecialchars($params['country']);
				$from[] = '/{{ phonenumber }}/';
				$to[] = htmlspecialchars($params['fullphonenumber']);
				$from[] = '/{{ email }}/';
				$to[] = htmlspecialchars($params['email']);
				$from[] = '/{{ authInfo }}/';
				$to[] = htmlspecialchars($s->generateObjectPW());
				$from[] = '/{{ clTRID }}/';
				$clTRID = str_replace('.', '', round(microtime(1), 3));
				$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-create-' . $clTRID);
				$from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
				$to[] = '';
				$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<create>
	  <contact:create
	   xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
		<contact:id>{{ id }}</contact:id>
		<contact:postalInfo type="loc">
		  <contact:name>{{ name }}</contact:name>
		  <contact:org>{{ org }}</contact:org>
		  <contact:addr>
			<contact:street>{{ street1 }}</contact:street>
			<contact:street>{{ street2 }}</contact:street>
			<contact:street>{{ street3 }}</contact:street>
			<contact:city>{{ city }}</contact:city>
			<contact:sp>{{ state }}</contact:sp>
			<contact:pc>{{ postcode }}</contact:pc>
			<contact:cc>{{ country }}</contact:cc>
		  </contact:addr>
		</contact:postalInfo>
		<contact:voice>{{ phonenumber }}</contact:voice>
		<contact:fax></contact:fax>
		<contact:email>{{ email }}</contact:email>
		<contact:authInfo>
		  <contact:pw>{{ authInfo }}</contact:pw>
		</contact:authInfo>
	  </contact:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
				$r = $s->write($xml, __FUNCTION__);
				$r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->creData;
				$contacts[$i + 1] = $r->id;
			}
			else {
				$id = strtoupper($params['registrarprefix'] . '' . $contactType . '' . $params['domainid']);
				$contacts[$i + 1] = htmlspecialchars($id);
			}
		}

        foreach(array(
            'ns1',
            'ns2',
            'ns3',
            'ns4',
            'ns5'
        ) as $ns) {
            if (empty($params["{$ns}"])) {
                continue;
            }

		$from = $to = array();
		$from[] = '/{{ name }}/';
		$dns = htmlspecialchars($params["{$ns}"]);
		$idn_to_ascii = idn_to_ascii($dns);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<check>
	  <host:check
		xmlns:host="urn:ietf:params:xml:ns:host-1.0"
		xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
		<host:name>{{ name }}</host:name>
	  </host:check>
	</check>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;

		if (0 == (int)$r->cd[0]->name->attributes()->avail) {
			continue;
		}

		$from = $to = array();
		$from[] = '/{{ name }}/';
		$dns = htmlspecialchars($params["{$ns}"]);
		$idn_to_ascii = idn_to_ascii($dns);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<create>
	  <host:create
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
	  </host:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
}

		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ period }}/';
		$to[] = htmlspecialchars($params['regperiod']);
		$from[] = '/{{ ns1 }}/';
		$to[] = htmlspecialchars($params['ns1']);
		$from[] = '/{{ ns2 }}/';
		$to[] = htmlspecialchars($params['ns2']);
		$from[] = '/{{ ns3 }}/';
		$to[] = htmlspecialchars($params['ns3']);
		$from[] = '/{{ ns4 }}/';
		$to[] = htmlspecialchars($params['ns4']);
		$from[] = '/{{ ns5 }}/';
		$to[] = htmlspecialchars($params['ns5']);		
		$from[] = '/{{ cID_1 }}/';
		$to[] = htmlspecialchars($contacts[1]);
		$from[] = '/{{ cID_2 }}/';
		$to[] = htmlspecialchars($contacts[2]);
		$from[] = '/{{ authInfo }}/';
		$to[] = htmlspecialchars($s->generateObjectPW());
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-create-' . $clTRID);
		$from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
		$to[] = '';
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<create>
	  <domain:create
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
		<domain:period unit="y">{{ period }}</domain:period>
		<domain:ns>
		  <domain:hostObj>{{ ns1 }}</domain:hostObj>
		  <domain:hostObj>{{ ns2 }}</domain:hostObj>
		  <domain:hostObj>{{ ns3 }}</domain:hostObj>
		  <domain:hostObj>{{ ns4 }}</domain:hostObj>
		  <domain:hostObj>{{ ns5 }}</domain:hostObj>
		</domain:ns>
		<domain:registrant>{{ cID_1 }}</domain:registrant>
		<domain:contact type="tech">{{ cID_2 }}</domain:contact>
		<domain:authInfo>
		  <domain:pw>{{ authInfo }}</domain:pw>
		</domain:authInfo>
	  </domain:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

// Escape backreferences from string for use with regex
function _preg_escape_back($string) {
    // Replace $ with \$ and \ with \\
    $string = preg_replace('#(?<!\\\\)(\\$|\\\\)#', '\\\\$1', $string);
    return $string;
}

function nicch_TransferDomain($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ years }}/';
		$to[] = htmlspecialchars($params['regperiod']);
		$from[] = '/{{ authInfo_pw }}/';
		$to[] = htmlspecialchars($params['transfersecret']);
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-transfer-' . $clTRID);
		$xml = preg_replace($from, _preg_escape_back($to), '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<transfer op="request">
	  <domain:transfer
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
		<domain:period unit="y">{{ years }}</domain:period>
		<domain:authInfo>
		  <domain:pw>{{ authInfo_pw }}</domain:pw>
		</domain:authInfo>
	  </domain:transfer>
	</transfer>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
		$trStatus = (string)$r->trStatus;
		$updatedDomainTrStatus = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['trstatus' => $trStatus]);

		if ($trStatus === 'serverApproved') {
			$updatedDomain = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['status' => 'Active']);

			// daca e cu success facem update cu alt contact
			// verificam daca este deja acest contact
			$contacts = array();
			foreach(array(
				'registrant',
				'tech'
			) as $i => $contactType) {
				$from = $to = array();
				$from[] = '/{{ id }}/';
				$id = strtoupper($params['registrarprefix'] . '' . $contactType . '' . $params['domainid']);
				$to[] = htmlspecialchars($id);
				$from[] = '/{{ clTRID }}/';
				$clTRID = str_replace('.', '', round(microtime(1), 3));
				$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-check-' . $clTRID); // vezi la create tot acest id sa fie
				$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<check>
	  <contact:check
		xmlns:contact="urn:ietf:params:xml:ns:contact-1.0"
		xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
		<contact:id>{{ id }}</contact:id>
	  </contact:check>
	</check>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
				$r = $s->write($xml, __FUNCTION__);
				$r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->chkData;

				//		$reason = (string)$r->cd[0]->reason;
				//		if (!$reason) {
				//			$reason = 'Contact is not available';
				//		}

				if (1 == (int) $r->cd[0]->id->attributes()->avail) {

					// contact:create

					$from = $to = array();
					$from[] = '/{{ id }}/';
					$id = strtoupper($params['registrarprefix'] . '' . $contactType . '' . $params['domainid']); // vezi la check tot acest id sa fie
					$to[] = htmlspecialchars($id);
					$from[] = '/{{ name }}/';
					$to[] = htmlspecialchars($params['firstname'] . ' ' . $params['lastname']);
					$from[] = '/{{ org }}/';
					$to[] = htmlspecialchars($params['companyname']);
					$from[] = '/{{ street1 }}/';
					$to[] = htmlspecialchars($params['address1']);
					$from[] = '/{{ street2 }}/';
					$to[] = htmlspecialchars($params['address2']);
					$from[] = '/{{ street3 }}/';
					$street3 = (isset($params['address3']) ? $params['address3'] : '');
					$to[] = htmlspecialchars($street3);
					$from[] = '/{{ city }}/';
					$to[] = htmlspecialchars($params['city']);
					$from[] = '/{{ state }}/';
					$to[] = htmlspecialchars($params['state']);
					$from[] = '/{{ postcode }}/';
					$to[] = htmlspecialchars($params['postcode']);
					$from[] = '/{{ country }}/';
					$to[] = htmlspecialchars($params['country']);
					$from[] = '/{{ phonenumber }}/';
					$to[] = htmlspecialchars($params['fullphonenumber']);
					$from[] = '/{{ email }}/';
					$to[] = htmlspecialchars($params['email']);
					$from[] = '/{{ authInfo }}/';
					$to[] = htmlspecialchars($s->generateObjectPW());
					$from[] = '/{{ clTRID }}/';
					$clTRID = str_replace('.', '', round(microtime(1), 3));
					$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-create-' . $clTRID);
					$from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
					$to[] = '';
					$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<create>
	  <contact:create
	   xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
		<contact:id>{{ id }}</contact:id>
		<contact:postalInfo type="loc">
		  <contact:name>{{ name }}</contact:name>
		  <contact:org>{{ org }}</contact:org>
		  <contact:addr>
			<contact:street>{{ street1 }}</contact:street>
			<contact:street>{{ street2 }}</contact:street>
			<contact:street>{{ street3 }}</contact:street>
			<contact:city>{{ city }}</contact:city>
			<contact:sp>{{ state }}</contact:sp>
			<contact:pc>{{ postcode }}</contact:pc>
			<contact:cc>{{ country }}</contact:cc>
		  </contact:addr>
		</contact:postalInfo>
		<contact:voice>{{ phonenumber }}</contact:voice>
		<contact:fax></contact:fax>
		<contact:email>{{ email }}</contact:email>
		<contact:authInfo>
		  <contact:pw>{{ authInfo }}</contact:pw>
		</contact:authInfo>
	  </contact:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
					$r = $s->write($xml, __FUNCTION__);
					$r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->creData;
					$contacts[$i + 1] = $r->id;
				}
				else {
					$id = strtoupper($params['registrarprefix'] . '' . $contactType . '' . $params['domainid']);
					$contacts[$i + 1] = htmlspecialchars($id);
				}
			}	
			// apoi facem domain:chg

			$from = $to = array();
			$from[] = '/{{ name }}/';
			$domainname = htmlspecialchars($params['domainname']);
			$idn_to_ascii = idn_to_ascii($domainname);
			$to[] = $idn_to_ascii;
			$from[] = '/{{ cID_1 }}/';
			$to[] = htmlspecialchars($contacts[1]);
			$from[] = '/{{ cID_2 }}/';
			$to[] = htmlspecialchars($contacts[2]);
			$from[] = '/{{ authInfo }}/';
			$to[] = htmlspecialchars($s->generateObjectPW());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
			$from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
			$to[] = '';
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <domain:update
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
         <domain:add>
            <domain:contact type="tech">{{ cID_2 }}</domain:contact>
         </domain:add>
         <domain:chg>
            <domain:registrant>{{ cID_1 }}</domain:registrant>
         </domain:chg>
	  </domain:update>
	</update>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}

	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_GetNameservers($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$rd = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
		$i = 0;
		foreach($rd->ns->hostObj as $ns) {
			$i++;
			$return["ns{$i}"] = idn_to_utf8($ns);
		}

		$status = array();
		Capsule::table('epp_domain_status')->where('domain_id', '=', $params['domainid'])->delete();
		foreach($rd->status as $e) {
			$st = (string)$e->attributes()->s;
//			if ($st == 'pendingDelete') {
//				$updatedDomainStatus = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['status' => 'Cancelled']);
//			}

			Capsule::table('epp_domain_status')->insert(['domain_id' => $params['domainid'], 'status' => $st]);
		}

		if ($r->response->extension && $r->response->extension->children('urn:ietf:params:xml:ns:rgp-1.0')->infData) {
			$re = $r->response->extension->children('urn:ietf:params:xml:ns:rgp-1.0')->infData;
			if ('redemptionPeriod' == (string)$re->rgpStatus->attributes()->s) {
				$updatedDomainStatus = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['status' => 'Cancelled']);
			}	
		}
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_SaveNameservers($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
		$add = $rem = array();
		$i = 0;
		foreach($r->ns->hostObj as $ns) {
			$i++;
			$ns = (string)$ns;
			if (!$ns) {
				continue;
			}

			$rem["ns{$i}"] = strtoupper($ns);
		}

// am pus original aici
		foreach($params['original'] as $k => $v) {
			if (!$v) {
				continue;
			}

			if (!preg_match("/^ns\d$/i", $k)) {
				continue;
			}

			$v = strtoupper($v);
			if ($k0 = array_search($v, $rem)) {
				unset($rem[$k0]);
			}
			else {
				$add[$k] = strtoupper($v);
			}
		}

// mai intii verificam daca este asa ns, daca nu, il vom crea
		if (!empty($add)) {
			foreach($add as $k => $v) {
				$from = $to = array();
				$from[] = '/{{ name }}/';
				$vname = htmlspecialchars($v);
				$idn_to_ascii = idn_to_ascii($vname);
				$to[] = $idn_to_ascii;
				$from[] = '/{{ clTRID }}/';
				$clTRID = str_replace('.', '', round(microtime(1), 3));
				$to[] = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);
				$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<check>
	  <host:check
		xmlns:host="urn:ietf:params:xml:ns:host-1.0"
		xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
		<host:name>{{ name }}</host:name>
	  </host:check>
	</check>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
				$r = $s->write($xml, __FUNCTION__);
				$r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;

				if (0 == (int)$r->cd[0]->name->attributes()->avail) {
					continue;
				}

				$from = $to = array();
				$from[] = '/{{ name }}/';
				$to[] = htmlspecialchars($v);
				$from[] = '/{{ clTRID }}/';
				$clTRID = str_replace('.', '', round(microtime(1), 3));
				$to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
				$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<create>
	  <host:create
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
	  </host:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
				$r = $s->write($xml, __FUNCTION__);
			}
		}
//
		if (!empty($add) || !empty($rem)) {
//			print_r($add);
//			echo "string";
//			print_r($rem);
//			exit();

		if ($add != $rem) {
			$from = $to = array();
			$text = '';
			foreach($add as $k => $v) {
				$vname = htmlspecialchars($v);
				$idn_to_ascii = idn_to_ascii($vname);
				$text .= '<domain:hostObj>' . $idn_to_ascii . '</domain:hostObj>' . "\n";
			}

			$from[] = '/{{ add }}/';
			$to[] = (empty($text) ? '' : "<domain:add><domain:ns>\n{$text}</domain:ns></domain:add>\n");
			$text = '';
			foreach($rem as $k => $v) {
				$vname = htmlspecialchars($v);
				$idn_to_ascii = idn_to_ascii($vname);
				$text .= '<domain:hostObj>' . $idn_to_ascii . '</domain:hostObj>' . "\n";
			}

			$from[] = '/{{ rem }}/';
			$to[] = (empty($text) ? '' : "<domain:rem><domain:ns>\n{$text}</domain:ns></domain:rem>\n");
			$from[] = '/{{ name }}/';
			$domainname = htmlspecialchars($params['original']['domainname']);
			$idn_to_ascii = idn_to_ascii($domainname);
			$to[] = $idn_to_ascii;
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <domain:update
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
	{{ add }}
	{{ rem }}
	  </domain:update>
	</update>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}
		}
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_GetContactDetails($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
		$dcontact = array();
		$dcontact['registrant'] = (string)$r->registrant;
		foreach($r->contact as $e) {
			$type = (string)$e->attributes()->type;
			$dcontact[$type] = (string)$e;
		}

		$contact = array();
		foreach($dcontact as $id) {
			if (isset($contact[$id])) {
				continue;
			}

			$from = $to = array();
			$from[] = '/{{ id }}/';
			$to[] = htmlspecialchars($id);
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <contact:info
	   xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
		<contact:id>{{ id }}</contact:id>
	  </contact:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->infData[0];
			$contact[$id] = array();
			$c = & $contact[$id];
			foreach($r->postalInfo as $e) {
				$c["Name"] = (string)$e->name;
				$c["Organization"] = (string)$e->org;
				for ($i = 0; $i <= 2; $i++) {
					$c["Street " . ($i + 1) ] = (string)$e->addr->street[$i];
				}

				if (empty($c["Street 3"])) {
					unset($c["street3"]);
				}

				$c["City"] = (string)$e->addr->city;
				$c["State or Province"] = (string)$e->addr->sp;
				$c["Postal Code"] = (string)$e->addr->pc;
				$c["Country Code"] = (string)$e->addr->cc;
				break;
			}

			$c["Phone"] = (string)$r->voice;
			$c["Fax"] = (string)$r->fax;
			$c["Email"] = (string)$r->email;
		}

		foreach($dcontact as $type => $id) {
			if ($type == 'registrant') {
				$type = 'Registrant';
			}
			elseif ($type == 'tech') {
				$type = 'Technical';
			}
			else {
				continue;
			}

			$return[$type] = $contact[$id];
		}
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_SaveContactDetails($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
		$dcontact = array();
		$dcontact['registrant'] = (string)$r->registrant;
		foreach($r->contact as $e) {
			$type = (string)$e->attributes()->type;
			$dcontact[$type] = (string)$e;
		}

		foreach($dcontact as $type => $id) {
			$a = array();
			if ($type == 'registrant') {
				$a = $params['contactdetails']['Registrant'];
			}
			elseif ($type == 'tech') {
				$a = $params['contactdetails']['Technical'];
			}

			if (empty($a)) {
				continue;
			}

// ----- aici aducem contact details

			$from = $to = array();
			$from[] = '/{{ id }}/';
			$to[] = htmlspecialchars($id);
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <contact:info
	   xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
		<contact:id>{{ id }}</contact:id>
	  </contact:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->infData[0];
			$contact[$id] = array();
			$c = & $contact[$id];
			foreach($r->postalInfo as $e) {
				$c["Name"] = (string)$e->name;
				$c["Organization"] = (string)$e->org;
				for ($i = 0; $i <= 2; $i++) {
					$c["Street " . ($i + 1) ] = (string)$e->addr->street[$i];
				}

//				if (empty($c["Street 3"])) {
//					unset($c["street3"]);
//				}

				$c["City"] = (string)$e->addr->city;
				$c["State or Province"] = (string)$e->addr->sp;
				$c["Postal Code"] = (string)$e->addr->pc;
				$c["Country Code"] = (string)$e->addr->cc;
				break;
			}

			$c["Phone"] = (string)$r->voice;
			$c["Fax"] = (string)$r->fax;
			$c["Email"] = (string)$r->email;

$a1_name = htmlspecialchars($c["Name"]);
$a1_org = htmlspecialchars($c["Organization"]);
$a1_street1 = htmlspecialchars($c["Street 1"]);
$a1_street2 = htmlspecialchars($c["Street 2"]);
$a1_street3 = htmlspecialchars($c["Street 3"]);
$a1_city = htmlspecialchars($c["City"]);
$a1_sp = htmlspecialchars($c["State or Province"]);
$a1_pc = htmlspecialchars($c["Postal Code"]);
$a1_cc = htmlspecialchars($c["Country Code"]);
$a1_phone = htmlspecialchars($c["Phone"]);
$a1_fax = htmlspecialchars($c["Fax"]);
$a1_email = htmlspecialchars($c["Email"]);

$a1 = array("Name" => trim($a1_name),
	"Organization" => trim($a1_org),
	"Street 1" => trim($a1_street1),
	"Street 2" => trim($a1_street2),
	"Street 3" => trim($a1_street3),
	"City" => trim($a1_city),
	"State or Province" => trim($a1_sp),
	"Postal Code" => trim($a1_pc),
	"Country Code" => trim($a1_cc),
	"Phone" => trim($a1_phone),
	"Fax" => trim($a1_fax),
	"Email" => trim($a1_email));

// ----- 

			$from = $to = array();

			$from[] = '/{{ id }}/';
			$to[] = htmlspecialchars($id);

			$from[] = '/{{ name }}/';
			$name = ($a['Name'] ? $a['Name'] : $a['Full Name']);
			$a2_name = htmlspecialchars(trim($name));
			$to[] = $a2_name;

			$from[] = '/{{ org }}/';
			$org = ($a['Organization'] ? $a['Organization'] : $a['Organisation Name']);
			$a2_org = htmlspecialchars(trim($org));
			$to[] = $a2_org;

			$from[] = '/{{ street1 }}/';
			$street1 = ($a['Street 1'] ? $a['Street 1'] : $a['Address 1']);
			$a2_street1 = htmlspecialchars(trim($street1));
			$to[] = $a2_street1;

			$from[] = '/{{ street2 }}/';
			$street2 = ($a['Street 2'] ? $a['Street 2'] : $a['Address 2']);
			$a2_street2 = htmlspecialchars(trim($street2));
			$to[] = $a2_street2;

			$from[] = '/{{ street3 }}/';
			$street3 = ($a['Street 3'] ? $a['Street 3'] : $a['Address 3']);
			$a2_street3 = htmlspecialchars(trim($street3));
			$to[] = $a2_street3;

			$from[] = '/{{ city }}/';
			$a2_city = htmlspecialchars(trim($a['City']));
			$to[] = $a2_city;

			$from[] = '/{{ sp }}/';
			$sp = ($a['State or Province'] ? $a['State or Province'] : $a['State']);
			$a2_sp = htmlspecialchars(trim($sp));
			$to[] = $a2_sp;

			$from[] = '/{{ pc }}/';
			$pc = ($a['Postal Code'] ? $a['Postal Code'] : $a['Postcode']);
			$a2_pc = htmlspecialchars(trim($pc));
			$to[] = $a2_pc;

			$from[] = '/{{ cc }}/';
			$cc = ($a['Country Code'] ? $a['Country Code'] : $a['Country']);
			$a2_cc = htmlspecialchars(trim($cc));
			$to[] = $a2_cc;

			$from[] = '/{{ voice }}/';
			$a2_phone = htmlspecialchars(trim($a['Phone']));
			$to[] = $a2_phone;

			$from[] = '/{{ fax }}/';
			$a2_fax = htmlspecialchars(trim($a['Fax']));
			$to[] = $a2_fax;

			$from[] = '/{{ email }}/';
			$a2_email = htmlspecialchars(trim($a['Email']));
			$to[] = $a2_email;

$a2 = array("Name" => $a2_name,
	"Organization" => $a2_org,
	"Street 1" => $a2_street1,
	"Street 2" => $a2_street2,
	"Street 3" => $a2_street3,
	"City" => $a2_city,
	"State or Province" => $a2_sp,
	"Postal Code" => $a2_pc,
	"Country Code" => $a2_cc,
	"Phone" => $a2_phone,
	"Fax" => $a2_fax,
	"Email" => $a2_email);

//print_r($a1);
//echo "\n";
//print_r($a2);
//exit();

if ($a1 == $a2) {
	continue;
}

			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-chg-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <contact:update xmlns:contact="urn:ietf:params:xml:ns:contact-1.0" xsi:schemaLocation="urn:ietf:params:xml:ns:contact-1.0 contact-1.0.xsd">
		<contact:id>{{ id }}</contact:id>
		<contact:chg>
		  <contact:postalInfo type="loc">
			<contact:name>{{ name }}</contact:name>
			<contact:org>{{ org }}</contact:org>
			<contact:addr>
			  <contact:street>{{ street1 }}</contact:street>
			  <contact:street>{{ street2 }}</contact:street>
			  <contact:street>{{ street3 }}</contact:street>
			  <contact:city>{{ city }}</contact:city>
			  <contact:sp>{{ sp }}</contact:sp>
			  <contact:pc>{{ pc }}</contact:pc>
			  <contact:cc>{{ cc }}</contact:cc>
			</contact:addr>
		  </contact:postalInfo>
		  <contact:voice>{{ voice }}</contact:voice>
		  <contact:fax>{{ fax }}</contact:fax>
		  <contact:email>{{ email }}</contact:email>
		</contact:chg>
	  </contact:update>
	</update>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_GetEPPCode($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$eppcode = htmlspecialchars($s->generateObjectPW());
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ authInfo }}/';
		$to[] = $eppcode;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <domain:update
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
		<domain:chg>
		 <domain:authInfo>
		  <domain:pw>{{ authInfo }}</domain:pw>
		 </domain:authInfo>
		</domain:chg>
	  </domain:update>
	</update>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);

		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;

// If EPP Code is returned, return it for display to the end user
//	if (!empty($s)) {
//		$s->logout($params['registrarprefix']);
//	}
//return array('eppcode' => $eppcode);

		$from = $to = array();
		$from[] = '/{{ id }}/';

		// trimitem la adresa registrant

		$to[] = htmlspecialchars((string)$r->registrant);
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-contact-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <contact:info
	   xmlns:contact="urn:ietf:params:xml:ns:contact-1.0">
		<contact:id>{{ id }}</contact:id>
	  </contact:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:contact-1.0')->infData[0];
		$toEmail = (string)$r->email;
		global $CONFIG;
		$mail = new PHPMailer();
		$mail->From = $CONFIG['SystemEmailsFromEmail'];
		$mail->FromName = $CONFIG['SystemEmailsFromName'];
		$mail->Subject = strtoupper($params['original']['domainname']) . ' >> Information You Requested ';
		$mail->CharSet = $CONFIG['Charset'];
		if ($CONFIG['MailType'] == 'mail') {
			$mail->Mailer = 'mail';
		}
		else {
			$mail->IsSMTP();
			$mail->Host = $CONFIG['SMTPHost'];
			$mail->Port = $CONFIG['SMTPPort'];
			$mail->Hostname = $_SERVER['SERVER_NAME'];
			if ($CONFIG['SMTPSSL']) {
				$mail->SMTPSecure = $CONFIG['SMTPSSL'];
			}

			if ($CONFIG['SMTPUsername']) {
				$mail->SMTPAuth = true;
				$mail->Username = $CONFIG['SMTPUsername'];
				$mail->Password = decrypt($CONFIG['SMTPPassword']);
			}

			$mail->Sender = $CONFIG['Email'];
		}

		$mail->AddAddress($toEmail);
		$message = "
=============================================
DOMAIN INFORMATION YOU REQUESTED
=============================================

The authorization information you requested is as follows:

Domain Name: " . strtoupper($params['original']['domainname']) . "

Authorization Info: " . $eppcode . "

Regards,
" . $CONFIG['CompanyName'] . "
" . $CONFIG['Domain'] . "


--------------------------------------------------------------------------------
Copyright (C) " . date('Y') . " " . $CONFIG['CompanyName'] . " All rights reserved.
";
		$mail->Body = nl2br(htmlspecialchars($message));
		$mail->AltBody = $message; //text
		if (!$mail->Send()) {
			_nicch_log(__FUNCTION__, $mail);
			throw new exception('There has been an error sending the message. ' . $mail->ErrorInfo);
		}

		$mail->ClearAddresses();
	}

	catch(phpmailerException $e) {
		$return = array(
			'error' => 'There has been an error sending the message. ' . $e->getMessage()
		);
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_RegisterNameserver($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$nameserver = htmlspecialchars($params['nameserver']);
		$idn_to_ascii = idn_to_ascii($nameserver);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-host-check-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<check>
	  <host:check
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
	  </host:check>
	</check>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;
		if (0 == (int)$r->cd[0]->name->attributes()->avail) {
			throw new exception($r->cd[0]->name . " " . $r->cd[0]->reason);
		}

		$from = $to = array();
		$from[] = '/{{ name }}/';
		$nameserver = htmlspecialchars($params['nameserver']);
		$idn_to_ascii = idn_to_ascii($nameserver);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ ip }}/';
		$to[] = htmlspecialchars($params['ipaddress']);
		$from[] = '/{{ v }}/';
		$to[] = (preg_match('/:/', $params['ipaddress']) ? 'v6' : 'v4');
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<create>
	  <host:create
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
		<host:addr ip="{{ v }}">{{ ip }}</host:addr>
	  </host:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_ModifyNameserver($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$nameserver = htmlspecialchars($params['nameserver']);
		$idn_to_ascii = idn_to_ascii($nameserver);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ ip1 }}/';
		$to[] = htmlspecialchars($params['currentipaddress']);
		$from[] = '/{{ v1 }}/';
		$to[] = (preg_match('/:/', $params['currentipaddress']) ? 'v6' : 'v4');
		$from[] = '/{{ ip2 }}/';
		$to[] = htmlspecialchars($params['newipaddress']);
		$from[] = '/{{ v2 }}/';
		$to[] = (preg_match('/:/', $params['newipaddress']) ? 'v6' : 'v4');
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-host-update-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <host:update
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
		<host:add>
		  <host:addr ip="{{ v2 }}">{{ ip2 }}</host:addr>
		</host:add>
		<host:rem>
		  <host:addr ip="{{ v1 }}">{{ ip1 }}</host:addr>
		</host:rem>
	  </host:update>
	</update>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_DeleteNameserver($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$nameserver = htmlspecialchars($params['nameserver']);
		$idn_to_ascii = idn_to_ascii($nameserver);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-host-delete-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<delete>
	  <host:delete
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
	  </host:delete>
	</delete>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_RequestDelete($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-delete-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<delete>
	  <domain:delete
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:delete>
	</delete>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

/**
 * Display the 'Host Names' screen for a domain.
 * @param array $params Parameters from WHMCS
 * @return array
 */
function nicch_hostNames($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);

		if (isset($_POST['command']) && ($_POST['command'] === 'createHost')) {
			$host = $_POST['host'];
			$ipaddress_array = $_POST['ipaddress'];

			$from = $to = array();
			$from[] = '/{{ name }}/';
			$hostname = htmlspecialchars($host . '.' . $params['original']['domainname']);
			$idn_to_ascii = idn_to_ascii($hostname);
			$to[] = $idn_to_ascii;

			$text = '';
			foreach($ipaddress_array as $ipaddress) {
				$v = (preg_match('/:/', $ipaddress) ? 'v6' : 'v4');
				$text .= '<host:addr ip="' . $v . '">' . $ipaddress . '</host:addr>' . "\n";
			}

			$from[] = '/{{ addr }}/';
			$to[] = (empty($text) ? '' : $text);

			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-host-create-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<create>
	  <host:create
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
		{{ addr }}
	  </host:create>
	</create>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}

		if (isset($_POST['command']) && ($_POST['command'] === 'deleteHost')) {
			$host = $_POST['host'];

			$from = $to = array();
			$from[] = '/{{ name }}/';
			$hostname = htmlspecialchars($host);
			$idn_to_ascii = idn_to_ascii($hostname);
			$to[] = $idn_to_ascii;

			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-host-delete-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<delete>
	  <host:delete
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0">
		<host:name>{{ name }}</host:name>
	  </host:delete>
	</delete>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}

		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;

		$hostList = array();
		$i = 0;
		foreach($r->host as $host) {
			$i++;
			$hostList[$i] = array(
				'host' => idn_to_utf8($host), 
				'ips' => array(),
			);

			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = $host;
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-host-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <host:info
	   xmlns:host="urn:ietf:params:xml:ns:host-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
		<host:name>{{ name }}</host:name>
	  </host:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->infData;

			foreach($r->addr as $ip) {
				$ipV = (string)$ip->attributes()->ip;
				$hostList[$i]['ips'][] = array(
					'ip' => (string)$ip,
					'v' => (string)$ipV,
				);
			}
		}

		if ($i > 0) {
			$hosts = 'YES';
		}
		else {
			$hosts = "Hostnames let you use your domain — instead of an IP address — to identify your name servers.";
		}

		$return = array(
			'templatefile' => 'hostNames',
			'requirelogin' => true,
			'vars' => array(
				'domainname' => $domainname,
				'hosts' => $hosts,
				'hostList' => $hostList
			)
		);
	}

	catch(exception $e) {
		$return = array(
			'templatefile' => 'hostNames',
			'requirelogin' => true,
			'vars' => array(
				'error' => $e->getMessage()
			)
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

/**
 * Display the 'DNSSECDSRecords' screen for a domain.
 * @param array $params Parameters from WHMCS
 * @return array
 */
function nicch_manageDNSSECDSRecords($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);

		if (isset($_POST['command']) && ($_POST['command'] === 'secDNSadd')) {
			$keyTag = $_POST['keyTag'];
			$alg = $_POST['alg'];
			$digestType = $_POST['digestType'];
			$digest = $_POST['digest'];

			$from = $to = array();
			$from[] = '/{{ name }}/';
			$domainname = htmlspecialchars($params['original']['domainname']);
			$idn_to_ascii = idn_to_ascii($domainname);
			$to[] = $idn_to_ascii;

			$from[] = '/{{ keyTag }}/';
			$to[] = htmlspecialchars($keyTag);

			$from[] = '/{{ alg }}/';
			$to[] = htmlspecialchars($alg);

			$from[] = '/{{ digestType }}/';
			$to[] = htmlspecialchars($digestType);

			$from[] = '/{{ digest }}/';
			$to[] = htmlspecialchars($digest);

			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <domain:update
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:update>
	</update>
    <extension>
      <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
        <secDNS:add>
          <secDNS:dsData>
            <secDNS:keyTag>{{ keyTag }}</secDNS:keyTag>
            <secDNS:alg>{{ alg }}</secDNS:alg>
            <secDNS:digestType>{{ digestType }}</secDNS:digestType>
            <secDNS:digest>{{ digest }}</secDNS:digest>
          </secDNS:dsData>
        </secDNS:add>
      </secDNS:update>
    </extension>	
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}

		if (isset($_POST['command']) && ($_POST['command'] === 'secDNSrem')) {
			$keyTag = $_POST['keyTag'];
			$alg = $_POST['alg'];
			$digestType = $_POST['digestType'];
			$digest = $_POST['digest'];

			$from = $to = array();
			$from[] = '/{{ name }}/';
			$domainname = htmlspecialchars($params['original']['domainname']);
			$idn_to_ascii = idn_to_ascii($domainname);
			$to[] = $idn_to_ascii;

			$from[] = '/{{ keyTag }}/';
			$to[] = htmlspecialchars($keyTag);

			$from[] = '/{{ alg }}/';
			$to[] = htmlspecialchars($alg);

			$from[] = '/{{ digestType }}/';
			$to[] = htmlspecialchars($digestType);

			$from[] = '/{{ digest }}/';
			$to[] = htmlspecialchars($digest);

			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <domain:update
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:update>
	</update>
    <extension>
      <secDNS:update xmlns:secDNS="urn:ietf:params:xml:ns:secDNS-1.1">
        <secDNS:rem>
          <secDNS:dsData>
            <secDNS:keyTag>{{ keyTag }}</secDNS:keyTag>
            <secDNS:alg>{{ alg }}</secDNS:alg>
            <secDNS:digestType>{{ digestType }}</secDNS:digestType>
            <secDNS:digest>{{ digest }}</secDNS:digest>
          </secDNS:dsData>
        </secDNS:rem>
      </secDNS:update>
    </extension>	
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}

		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);

		$secDNSdsData = array();
		if ($r->response->extension && $r->response->extension->children('urn:ietf:params:xml:ns:secDNS-1.1')->infData) {
			$DSRecords = 'YES';
			$i = 0;
			$r = $r->response->extension->children('urn:ietf:params:xml:ns:secDNS-1.1')->infData;
			foreach($r->dsData as $dsData) {
				$i++;
				$secDNSdsData[$i]["domainid"] = (int)$params['domainid'];
				$secDNSdsData[$i]["keyTag"] = (string)$dsData->keyTag;
				$secDNSdsData[$i]["alg"] = (int)$dsData->alg;
				$secDNSdsData[$i]["digestType"] = (int)$dsData->digestType;
				$secDNSdsData[$i]["digest"] = (string)$dsData->digest;
			}
		}
		else {
			$DSRecords = "You don't have any DS records";
		}

		$return = array(
			'templatefile' => 'manageDNSSECDSRecords',
			'requirelogin' => true,
			'vars' => array(
				'DSRecords' => $DSRecords,
				'DSRecordslist' => $secDNSdsData
			)
		);
	}

	catch(exception $e) {
		$return = array(
			'templatefile' => 'manageDNSSECDSRecords',
			'requirelogin' => true,
			'vars' => array(
				'error' => $e->getMessage()
			)
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

/**
 * Buttons for the client area for custom functions.
 * @return array
 */
function nicch_ClientAreaCustomButtonArray()
{
	$buttonarray = array(
		Lang::Trans('Host Names') => 'hostNames',
		Lang::Trans('Manage DNSSEC DS Records') => 'manageDNSSECDSRecords'
	);
	
	return $buttonarray;
}

function nicch_AdminCustomButtonArray($params = array())
{
	return array(
		Lang::Trans('Restore Domain from redemptionPeriod') => 'restoreDomain'
	);
}

function nicch_restoreDomain($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['original']['domainname']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-update-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<update>
	  <domain:update
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
           <domain:chg/>
      </domain:update>
    </update>
       <extension>
         <rgp:update xmlns:rgp="urn:ietf:params:xml:ns:rgp-1.0"
          xsi:schemaLocation="urn:ietf:params:xml:ns:rgp-1.0 rgp-1.0.xsd">
           <rgp:restore op="request"/>
         </rgp:update>
       </extension>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_TransferSync($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domainname = htmlspecialchars($params['domain']);
		$idn_to_ascii = idn_to_ascii($domainname);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
		$expDate = (string)$r->exDate;

		$domain = Capsule::table('tbldomains')->where('id', $params['domainid'])->first();

		if (isset($domain->trstatus)) {
			switch ($domain->trstatus) {
				case 'pending':
					$return['completed'] = false;
				break;
				case 'clientApproved':
				case 'serverApproved':
					$return['completed'] = true;
					$return['expirydate'] = date('Y-m-d', is_numeric($expDate) ? $expDate : strtotime($expDate));
					$expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);

                    $updateNextdueDate = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['nextduedate' => $expDate]);
                    $updateNextInvoiceDate = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['nextinvoicedate' => $expDate]);
				break;
				case 'clientRejected':
				case 'clientCancelled':
				case 'serverCancelled':
					$return['failed'] = true;
					$return['reason'] = $domain->trstatus;
				break;
				default:
					$return = array(
						'error' => sprintf('invalid transfer status: %s', $domain->trstatus)
					);
				break;
			}
		}
		else {
			$return = array(
				'error' => sprintf('invalid transfer status: %s', 'Unknown')
			);
		}

		return $return;
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

function nicch_Sync($params = array())
{
	_nicch_log(__FUNCTION__, $params);
	$return = array();
	try {
		$s = _nicch_startEppClient($params);
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$domain = htmlspecialchars($params['domain']);
		$idn_to_ascii = idn_to_ascii($domain);
		$to[] = $idn_to_ascii;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-info-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name hosts="all">{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $s->write($xml, __FUNCTION__);
		$r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
		$expDate = (string)$r->exDate;
        $timestamp = strtotime($expDate);

        if ($timestamp === false) {
            return array(
            	'error' => 'Empty renewal date for domain: ' . $params['domain']
            );
        }

        $expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);

		$updatedDomainExpiryDate = Capsule::table('tbldomains')->where('id', $params['domainid'])->update(['expirydate' => $expDate]);
			
        // ---- aici trimitem comanda delete daca domeniul are `donotrenew` = 1 si mai este o zi pana la expirare
		$domain = Capsule::table('tbldomains')
			->where('id', '=', $params['domainid'])
			->where('donotrenew', '=', '1')
			->whereRaw( '`expirydate` >= CURRENT_DATE() AND `expirydate` < ADDDATE(CURRENT_DATE(), INTERVAL 1 DAY)' )
			->first();

		if (isset($domain->expirydate)) {
			//
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$domainname = htmlspecialchars($params['domain']);
			$idn_to_ascii = idn_to_ascii($domainname);
			$to[] = $idn_to_ascii;
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($params['registrarprefix'] . '-domain-delete-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<delete>
	  <domain:delete
	   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
	   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:delete>
	</delete>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $s->write($xml, __FUNCTION__);
		}
        // ----

        if ($timestamp < time()) {
            return array(
                'expirydate'    =>  $expDate,
                'expired'       =>  true
            );            
        }
        else {
            return array(
                'expirydate'    =>  $expDate,
                'active'        =>  true
            );
        }
	}

	catch(exception $e) {
		$return = array(
			'error' => $e->getMessage()
		);
	}

	if (!empty($s)) {
		$s->logout($params['registrarprefix']);
	}

	return $return;
}

class nicch_epp_client

{
	var $socket;
	var $isLogined = false;
	var $params;
	function __construct($params)
	{
		$this->params = $params;
		$verify_peer = false;
		if ($params['verify_peer'] == 'on') {
			$verify_peer = true;
		}
		$ssl = array(
			'verify_peer' => $verify_peer,
			'cafile' => $params['cafile'],
			'local_cert' => $params['local_cert'],
			'local_pk' => $params['local_pk'],
			'passphrase' => $params['passphrase']
		);
		$host = $params['host'];
		$port = $params['port'];

		if ($host) {
			$this->connect($host, $port, $ssl);
		}
	}

	function connect($host, $port = 700, $ssl, $timeout = 30)
	{
		ini_set('display_errors', true);
		error_reporting(E_ALL);

		// echo '<pre>';print_r($host);
		// print_r($this->params);
		// exit;

		if ($host != $this->params['host']) {
			throw new exception("Unknown EPP server '$host'");
		}

		$opts = array(
			'ssl' => array(
				'verify_peer' => $ssl['verify_peer'],
				/*'capath' => __DIR__ . '/capath/',*/
				'cafile' => __DIR__ . '/cafile/' . $ssl['cafile'],
				'local_cert' => __DIR__ . '/local_cert/' . $ssl['local_cert'],
				'local_pk' => __DIR__ . '/local_pk/' . $ssl['local_pk'],
				'passphrase' => $ssl['passphrase'],
				'allow_self_signed' => true
			)
		);
		$context = stream_context_create($opts);
		$this->socket = stream_socket_client("tlsv1.2://{$host}:{$port}", $errno, $errmsg, $timeout, STREAM_CLIENT_CONNECT, $context);


		if (!$this->socket) {
			throw new exception("Cannot connect to server '{$host}': {$errmsg}");
		}

		return $this->read();
	}

	function login($login, $pwd, $prefix)
	{
		$from = $to = array();
		$from[] = '/{{ clID }}/';
		$to[] = htmlspecialchars($login);
		$from[] = '/{{ pw }}/';
		$to[] = $pwd;
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($prefix . '-login-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<login>
	  <clID>{{ clID }}</clID>
	  <pw><![CDATA[{{ pw }}]]></pw>
	  <options>
		<version>1.0</version>
		<lang>en</lang>
	  </options>
	  <svcs>
		<objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
		<objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
		<objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
		<svcExtension>
		  <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
		  <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
		</svcExtension>
	  </svcs>
	</login>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $this->write($xml, __FUNCTION__);
		$this->isLogined = true;
		return true;
	}

	function logout($prefix)
	{
		if (!$this->isLogined) {
			return true;
		}

		$from = $to = array();
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($prefix . '-logout-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<logout/>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $this->write($xml, __FUNCTION__);
		$this->isLogined = false;
		return true;
	}

	function read()
	{
		_nicch_log('================= read-this =================', $this);
		if (feof($this->socket)) {
			throw new exception('Connection appears to have closed.');
		}

		$hdr = @fread($this->socket, 4);
		if (empty($hdr)) {
			throw new exception("Error reading from server: $php_errormsg");
		}

		$unpacked = unpack('N', $hdr);
		$xml = fread($this->socket, ($unpacked[1] - 4));
		$xml = preg_replace("/></", ">\n<", $xml);
		_nicch_log('================= read =================', $xml);
		return $xml;
	}

	function write($xml, $action = 'Unknown')
	{
		_nicch_log("================= send-this " . $action . "=================", $this);
		_nicch_log("================= send-xml " . $action . "=================", $xml);
		@fwrite($this->socket, pack('N', (strlen($xml) + 4)) . $xml);
		$r = $this->read();
		_nicch_modulelog($xml, $r, $action);
		$r = new SimpleXMLElement($r);
		if ($r->response->result->attributes()->code >= 2000) {
			throw new exception($r->response->result->msg . ' ' . $r->response->result->extValue->reason);
		}
		return $r;
	}

	function disconnect()
	{
		return @fclose($this->socket);
	}

	function generateObjectPW($objType = 'none')
	{
		$result = '';
		$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!=+-";
		$minLength = 13;
		$maxLength = 13;
		$length = mt_rand($minLength, $maxLength);
		while ($length--) {
			$result .= $chars[mt_rand(1, strlen($chars) - 1) ];
		}

		return 'aA1' . $result;
	}
}

function _nicch_modulelog($send, $responsedata, $action)
{
	$from = $to = array();
	$from[] = "/<clID>[^<]*<\/clID>/i";
	$to[] = '<clID>Not disclosed clID</clID>';
	$from[] = "/<pw>[^<]*<\/pw>/i";
	$to[] = '<pw>Not disclosed pw</pw>';
	$sendforlog = preg_replace($from, $to, $send);
	logModuleCall('nicch',$action,$sendforlog,$responsedata);
}

function _nicch_log($func, $params = false)
{

	//comment line below to see logs
	return true;

	$handle = fopen(dirname(__FILE__) . '/log/nicch.log', 'a');
	ob_start();
	echo "\n================= $func =================\n";
	print_r($params);
	$text = ob_get_contents();
	ob_end_clean();
	fwrite($handle, $text);
	fclose($handle);
}

function _nicch_create_table()
{

	//	Capsule::schema()->table('tbldomains', function (Blueprint $table) {
	//		$table->increments('id')->unsigned()->change();
	//	});

	if (!Capsule::schema()->hasTable('epp_domain_status')) {
		try {
			Capsule::schema()->create('epp_domain_status',
			function (Blueprint $table)
			{
				/** @var \Illuminate\Database\Schema\Blueprint $table */
				$table->increments('id');
				$table->integer('domain_id');

				// $table->integer('domain_id')->unsigned();

				$table->enum('status', array(
					'clientDeleteProhibited',
					'clientHold',
					'clientRenewProhibited',
					'clientTransferProhibited',
					'clientUpdateProhibited',
					'inactive',
					'ok',
					'pendingCreate',
					'pendingDelete',
					'pendingRenew',
					'pendingTransfer',
					'pendingUpdate',
					'serverDeleteProhibited',
					'serverHold',
					'serverRenewProhibited',
					'serverTransferProhibited',
					'serverUpdateProhibited'
				))->default('ok');
				$table->unique(array(
					'domain_id',
					'status'
				));
				$table->foreign('domain_id')->references('id')->on('tbldomains')->onDelete('cascade');
			});
		}

		catch(Exception $e) {
			echo "Unable to create table 'epp_domain_status': {$e->getMessage() }";
		}
	}
}

function _nicch_create_column()
{
	if (!Capsule::schema()->hasColumn('tbldomains', 'trstatus')) {
		try {
			Capsule::schema()->table('tbldomains',
			function (Blueprint $table)
			{
				$table->enum('trstatus', array(
					'clientApproved',
					'clientCancelled',
					'clientRejected',
					'pending',
					'serverApproved',
					'serverCancelled'
				))->nullable()->after('status');
			});
		}

		catch(Exception $e) {
			echo "Unable to alter table 'tbldomains' add column 'trstatus': {$e->getMessage() }";
		}
	}
}

?>