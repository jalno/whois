<?php
namespace packages\whois;
class nicco_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Holder Contact',
            'admin' => 'Admin Contact',
            'tech' => 'Tech. Contact',
            'domain.nserver.' => 'Nameservers',
            'domain.created' => 'Creation Date:',
            'domain.expires' => 'Expiration Date:'
        );

        $translate = array(
            'city:' => 'address.city',
            'org. name:' => 'organization',
            'address1:' => 'address.street.',
            'address2:' => 'address.street.',
            'state:' => 'address.state',
            'postal code:' => 'address.zip'
        );

        $r = get_blocks($data_str, $items, true);
        $r['owner'] = get_contact($r['owner'], $translate);
        $r['admin'] = get_contact($r['admin'], $translate, true);
        $r['tech'] = get_contact($r['tech'], $translate, true);
        return format_dates($r, 'dmy');
    }

}
