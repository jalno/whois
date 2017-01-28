<?php
namespace packages\whois;
class il_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'personname' => 'name',
            'address' => 'address'/* ,
                  'address' => 'address.city',
                  'address' => 'address.pcode',
                  'address' => 'address.country' */
        );

        $contacts = array(
            'registrant' => 'owner',
            'admin-c' => 'admin',
            'tech-c' => 'tech',
            'billing-c' => 'billing',
            'zone-c' => 'zone'
        );
//unset($data_str['rawdata'][19]);
        array_splice($data_str['rawdata'], 16, 1);
        array_splice($data_str['rawdata'], 18, 1);
//print_r($data_str['rawdata']);
//die;
        $reg = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');

        if (isset($reg['domain']['remarks']))
            unset($reg['domain']['remarks']);

        if (isset($reg['domain']['descr:'])) {
            while (list($key, $val) = each($reg['domain']['descr:'])) {
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

            if (isset($reg['domain']['descr:']))
                unset($reg['domain']['descr:']);
        }

        $r = array();
        $r['regrinfo'] = $reg;
        $r['regyinfo'] = array(
            'referrer' => 'http://www.isoc.org.il/',
            'registrar' => 'ISOC-IL'
        );
        return $r;
    }

}
