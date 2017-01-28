<?php
namespace packages\whois;
class ovh_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'billing' => 'Billing Contact:',
            'domain.sponsor' => 'Registrar of Record:',
            'domain.changed' => 'Record last updated on',
            'domain.expires' => 'Record expires on',
            'domain.created' => 'Record created on'
        );

        return easy_parser($data_str, $items, 'mdy', array(), false, true);
    }

}
