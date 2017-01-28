<?php
namespace packages\whois;
class nameintel_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant Contact:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact',
            'domain.name' => 'Domain Name:',
            'domain.status' => 'Status:',
            'domain.nserver' => 'Name Server:',
            'domain.created' => 'Creation Date:',
            'domain.expires' => 'Expiration Date:'
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
