<?php
namespace packages\whois;
class cz_handler {

    function parse($data_str, $query) {
        $translate = array(
            'expire' => 'expires',
            'registered' => 'created',
            'nserver' => 'nserver',
            'domain' => 'name',
            'contact' => 'handle',
            'reg-c' => '',
            'descr' => 'desc',
            'e-mail' => 'email',
            'person' => 'name',
            'org' => 'organization',
            'fax-no' => 'fax'
        );

        $contacts = array(
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'bill-c' => 'billing',
            'registrant' => 'owner'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'dmy');

        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.cz',
            'registrar' => 'CZ-NIC'
        );

        if ($data_str['rawdata'][0] == 'Your connection limit exceeded. Please slow down and try again later.') {
            $r['regrinfo']['registered'] = 'unknown';
        }

        return $r;
    }

}
