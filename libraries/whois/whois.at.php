<?php
namespace packages\whois;
class at_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'personname' => 'name',
            'street address' => 'address.street',
            'city' => 'address.city',
            'postal code' => 'address.pcode',
            'country' => 'address.country'
        );

        $contacts = array(
            'registrant' => 'owner',
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'billing-c' => 'billing',
            'zone-c' => 'zone'
        );

        $reg = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');

        if (isset($reg['domain']['remarks']))
            unset($reg['domain']['remarks']);

        if (isset($reg['domain']['descr'])) {
            while (list($key, $val) = each($reg['domain']['descr'])) {
                $v = trim(substr(strstr($val, ':'), 1));
                if (strstr($val, '[organization]:')) {
                    $reg['owner']['organization'] = $v;
                    continue;
                }
                if (strstr($val, '[phone]:')) {
                    $reg['owner']['phone'] = $v;
                    continue;
                }
                if (strstr($val, '[fax-no]:')) {
                    $reg['owner']['fax'] = $v;
                    continue;
                }
                if (strstr($val, '[e-mail]:')) {
                    $reg['owner']['email'] = $v;
                    continue;
                }

                $reg['owner']['address'][$key] = $v;
            }

            if (isset($reg['domain']['descr']))
                unset($reg['domain']['descr']);
        }

        $r = array();
        $r['regrinfo'] = $reg;
        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.at',
            'registrar' => 'NIC-AT'
        );
        return $r;
    }

}
