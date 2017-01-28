<?php
namespace packages\whois;
/**
 * IR Domain names lookup handler class.
 */
class ir_handler {

    function parse($data_str, $query) {
        $translate = array(
            'nic-hdl' => 'handle',
            'org' => 'organization',
            'e-mail' => 'email',
            'person' => 'name',
            'fax-no' => 'fax',
            'domain' => 'name',
            'expire-date' => 'expires',
            'last-updated' => 'changed'
        );

        $contacts = array(
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'holder-c' => 'owner'
        );

        $reg = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Y-m-d');

        $r = array();
        $r['regrinfo'] = $reg;
        $r['regyinfo'] = array(
            'referrer' => 'http://whois.nic.ir/',
            'registrar' => 'NIC-IR'
        );
        return $r;
    }

}
