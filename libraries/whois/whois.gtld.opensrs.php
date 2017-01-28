<?php
namespace packages\whois;
class opensrs_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact',
            'tech' => 'Technical Contact',
            'domain.name' => 'Domain name:',
            '' => 'Registration Service Provider:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.changed' => 'Record last updated on',
            'domain.created' => 'Record created on',
            'domain.expires' => 'Record expires on',
            'domain.sponsor' => 'Registrar of Record:'
        );

        $r = easy_parser($data_str, $items, 'dmy', array(), false, true);

        if (isset($r['domain']['sponsor']) && is_array($r['domain']['sponsor']))
            $r['domain']['sponsor'] = $r['domain']['sponsor'][0];

        return $r;
    }

}
