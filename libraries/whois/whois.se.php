<?php
namespace packages\whois;
class se_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain' => 'domain.name',
            'state:' => 'domain.status.',
            'status:' => 'domain.status.',
            'expires:' => 'domain.expires',
            'created:' => 'domain.created',
            'nserver:' => 'domain.nserver.',
            'holder:' => 'owner.handle'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items, 'ymd', false);

        $r['regrinfo']['registered'] = isset($r['regrinfo']['domain']['name']) ? 'yes' : 'no';

        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic-se.se',
            'registrar' => 'NIC-SE'
        );
        return $r;
    }

}
