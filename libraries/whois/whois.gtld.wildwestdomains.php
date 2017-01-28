<?php
namespace packages\whois;
class wildwestdomains_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative Contact:',
            'tech' => 'Technical Contact:',
            'domain.name' => 'Domain name:',
            'domain.sponsor' => 'Registered through:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.created' => 'Created on:',
            'domain.expires' => 'Expires on:',
            'domain.changed' => 'Last Updated on:'
        );

        return easy_parser($data_str, $items, 'mdy');
    }

}
