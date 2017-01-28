<?php
namespace packages\whois;
class markmonitor_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact, Zone Contact:',
            'domain.name' => 'Domain Name:',
            'domain.sponsor' => 'Registrar Name:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.created' => 'Created on..............:',
            'domain.expires' => 'Expires on..............:',
            'domain.changed' => 'Record last updated on..:'
        );

        $r = easy_parser($data_str, $items, 'dmy', array(), false, true);

        if (isset($r['domain']['sponsor']) && is_array($r['domain']['sponsor']))
            $r['domain']['sponsor'] = $r['domain']['sponsor'][0];

        foreach ($r as $key => $part) {
            if (isset($part['address'])) {
                $r[$key]['organization'] = array_shift($r[$key]['address']);
                $r[$key]['address']['country'] = array_pop($r[$key]['address']);
            }
        }
        return $r;
    }

}
