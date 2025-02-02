<?php
namespace packages\whois;
class fr_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'ns-list' => 'handle',
            'person' => 'name',
            'address' => 'address.',
            'descr' => 'desc',
            'anniversary' => '',
            'domain' => '',
            'last-update' => 'changed',
            'registered' => 'created',
            'country' => 'address.country',
            'registrar' => 'sponsor',
            'role' => 'organization'
        );

        $contacts = array(
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'zone-c' => 'zone',
            'holder-c' => 'owner',
            'nsl-id' => 'nserver'
        );

        $reg = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'dmY');

        if (isset($reg['nserver'])) {
            $reg['domain'] = array_merge($reg['domain'], $reg['nserver']);
            unset($reg['nserver']);
        }

        $r = array();
        $r['regrinfo'] = $reg;
        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.fr',
            'registrar' => 'AFNIC'
        );
        return $r;
    }

}
