<?php
namespace packages\whois;
class is_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'person' => 'name'
        );

        $contacts = array(
            'owner-c' => 'owner',
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'billing-c' => 'billing',
            'zone-c' => 'zone'
        );

        $reg = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'mdy');

        if (isset($reg['domain']['descr'])) {
            $reg['owner']['name'] = array_shift($reg['domain']['descr']);
            $reg['owner']['address'] = $reg['domain']['descr'];
            unset($reg['domain']['descr']);
        }

        $r = array();
        $r['regrinfo'] = $reg;
        $r['regyinfo'] = array(
            'referrer' => 'http://www.isnic.is',
            'registrar' => 'ISNIC'
        );
        return $r;
    }

}
