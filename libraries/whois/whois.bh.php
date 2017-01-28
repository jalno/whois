<?php
namespace packages\whois;
class bh_handler {

    function parse($data_str, $query) {
        $items = array(
            'Sponsoring Registrar Name:' => 'domain.sponsor.name',
            'Sponsoring Registrar Email:' => 'domain.sponsor.email',
            'Sponsoring Registrar Uri:' => 'domain.sponsor.uri',
            'Sponsoring Registrar Phone:' => 'domain.sponsor.phone'
        );
        $i = generic_parser_b($data_str['rawdata'], $items);

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata']);
        if (isset($r['regrinfo']['domain']) && is_array($r['regrinfo']['domain']))
            $r['regrinfo']['domain']['sponsor'] = $i['domain']['sponsor'];
        if (empty($r['regrinfo']['domain']['created']))
            $r['regrinfo']['registered'] = 'no';
        else
            $r['regrinfo']['registered'] = 'yes';
        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.bh/',
            'registrar' => 'NIC-BH'
        );
        return $r;
    }

}
