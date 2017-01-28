<?php
namespace packages\whois;
class au_handler {

    function parse($data_str, $query) {

        $items = array(
            'Domain Name:' => 'domain.name',
            'Last Modified:' => 'domain.changed',
            'Registrar Name:' => 'domain.sponsor',
            'Status:' => 'domain.status',
            'Domain ROID:' => 'domain.handle',
            'Registrant:' => 'owner.organization',
            'Registrant Contact ID:' => 'owner.handle',
            'Registrant Contact Email:' => 'owner.email',
            'Registrant Contact Name:' => 'owner.name',
            'Tech Contact Name:' => 'tech.name',
            'Tech Contact Email:' => 'tech.email',
            'Tech Contact ID:' => 'tech.handle',
            'Name Server:' => 'domain.nserver.'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items);
        $r['regyinfo'] = array(
            'referrer' => 'http://www.aunic.net',
            'registrar' => 'AU-NIC'
        );
        return $r;
    }

}
