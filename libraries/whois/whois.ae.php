<?php
namespace packages\whois;
class ae_handler {

    function parse($data_str, $query) {
        $items = array(
            'Domain Name:' => 'domain.name',
            'Registrar Name:' => 'domain.sponsor',
            'Status:' => 'domain.status',
            'Registrant Contact ID:' => 'owner.handle',
            'Registrant Contact Name:' => 'owner.name',
            'Tech Contact Name:' => 'tech.name',
            'Tech Contact ID:' => 'tech.handle',
            'Name Server:' => 'domain.nserver.'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items, 'ymd');

        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.ae',
            'registrar' => 'UAENIC'
        );

        return $r;
    }

}
