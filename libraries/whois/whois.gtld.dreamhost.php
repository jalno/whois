<?php
namespace packages\whois;
class dreamhost_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant Contact:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'billing' => 'Billing Contact:',
            'domain.name' => 'Domain Name:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.created' => 'Record created on',
            'domain.expires' => 'Record expires on'
        );

        $r = easy_parser($data_str, $items, 'dmy', array(), false, true);
        if (isset($r['domain']['sponsor']) && is_array($r['domain']['sponsor']))
            $r['domain']['sponsor'] = $r['domain']['sponsor'][0];
        return $r;
    }

}
