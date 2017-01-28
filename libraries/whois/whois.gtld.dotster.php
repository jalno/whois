<?php
namespace packages\whois;
class dotster_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrative',
            'tech' => 'Technical',
            'domain.nserver' =>
            'Domain servers in listed order:',
            'domain.name' => 'Domain name:',
            'domain.created' => 'Created on:',
            'domain.expires' => 'Expires on:',
            'domain.changed' => 'Last Updated on:',
            'domain.sponsor' => 'Registrar:'
        );

        return easy_parser($data_str, $items, 'dmy');
    }

}
