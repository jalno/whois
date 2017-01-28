<?php
namespace packages\whois;
class domainpeople_handler {

    function parse($data_str, $query) {

        $items = array(
            'owner' => 'Registrant Contact:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'domain.name' => 'Domain name:',
            'domain.sponsor' => 'Registration Service Provided By:',
            'domain.referrer' => 'Contact:',
            'domain.nserver.' => 'Name Servers:',
            'domain.created' => 'Creation date:',
            'domain.expires' => 'Expiration date:',
//            'domain.changed' => 'Record last updated on',
            'domain.status' => 'Status:'
        );

        $r = easy_parser($data_str, $items, 'dmy', array(), false, true);
        if (isset($r['domain']['sponsor']) && is_array($r['domain']['sponsor']))
            $r['domain']['sponsor'] = $r['domain']['sponsor'][0];
        return $r;
    }

}
