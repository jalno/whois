<?php
namespace packages\whois;
class lacnic_handler {

    function parse($data_str, $query) {
        $translate = array(
            'fax-no' => 'fax',
            'e-mail' => 'email',
            'nic-hdl-br' => 'handle',
            'nic-hdl' => 'handle',
            'person' => 'name',
            'netname' => 'name',
            'descr' => 'desc',
            'country' => 'address.country'
        );

        $contacts = array(
            'owner-c' => 'owner',
            'tech-c' => 'tech',
            'abuse-c' => 'abuse',
            'admin-c' => 'admin'
        );

        $r = generic_parser_a($data_str, $translate, $contacts, 'network');

        unset($r['network']['owner']);
        unset($r['network']['ownerid']);
        unset($r['network']['responsible']);
        unset($r['network']['address']);
        unset($r['network']['phone']);
        unset($r['network']['aut-num']);
        unset($r['network']['nsstat']);
        unset($r['network']['nslastaa']);
        unset($r['network']['inetrev']);

        if (!empty($r['network']['aut-num']))
            $r['network']['handle'] = $r['network']['aut-num'];

        if (isset($r['network']['nserver']))
            $r['network']['nserver'] = array_unique($r['network']['nserver']);

        $r = array('regrinfo' => $r);
        $r['regyinfo']['type'] = 'ip';
        $r['regyinfo']['registrar'] = 'Latin American and Caribbean IP address Regional Registry';
        return $r;
    }

}
