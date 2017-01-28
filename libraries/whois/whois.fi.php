<?php
namespace packages\whois;
class fi_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain:' => 'domain.name',
            'created:' => 'domain.created',
            'expires:' => 'domain.expires',
            'status:' => 'domain.status',
            'nserver:' => 'domain.nserver.',
            'descr:' => 'owner.name.',
            'address:' => 'owner.address.',
            'phone:' => 'owner.phone',
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items);

        $r['regyinfo'] = array(
            'referrer' => 'https://domain.ficora.fi/',
            'registrar' => 'Finnish Communications Regulatory Authority'
        );
        return $r;
    }

}
