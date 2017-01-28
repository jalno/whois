<?php
namespace packages\whois;
class br_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl-br' => 'handle',
            'person' => 'name',
            'netname' => 'name',
            'domain' => 'name',
            'updated' => ''
        );

        $contacts = array(
            'owner-c' => 'owner',
            'tech-c' => 'tech',
            'admin-c' => 'admin',
            'billing-c' => 'billing'
        );

        $r = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');

        if (in_array('Permission denied.', $r['disclaimer'])) {
            $r['registered'] = 'unknown';
            return $r;
        }

        if (isset($r['domain']['nsstat']))
            unset($r['domain']['nsstat']);
        if (isset($r['domain']['nslastaa']))
            unset($r['domain']['nslastaa']);

        if (isset($r['domain']['owner'])) {
            $r['owner']['organization'] = $r['domain']['owner'];
            unset($r['domain']['owner']);
        }

        if (isset($r['domain']['responsible']))
            unset($r['domain']['responsible']);
        if (isset($r['domain']['address']))
            unset($r['domain']['address']);
        if (isset($r['domain']['phone']))
            unset($r['domain']['phone']);

        $a = array();
        $a['regrinfo'] = $r;
        $a['regyinfo'] = array(
            'registrar' => 'BR-NIC',
            'referrer' => 'http://www.nic.br'
        );
        return $a;
    }

}
