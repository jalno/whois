<?php
namespace packages\whois;
class onlinenic_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner' => 'Registrant:',
            'admin' => 'Administrator:',
            'tech' => 'Technical Contactor:',
            'billing' => 'Billing Contactor:',
            'domain.name' => 'Domain name:',
            'domain.name#' => 'Domain Name:',
            'domain.nserver' => 'Domain servers in listed order:',
            'domain.created' => 'Record created on ',
            'domain.expires' => 'Record expired on ',
            'domain.changed' => 'Record last updated at '
        );

        $extra = array(
            'tel--' => 'phone',
            'tel:' => 'phone',
            'tel --:' => 'phone',
            'email-:' => 'email',
            'email:' => 'email',
            'mail:' => 'email',
            'name--' => 'name',
            'org:' => 'organization',
            'zipcode:' => 'address.pcode',
            'postcode:' => 'address.pcode',
            'address:' => 'address.street',
            'city:' => 'address.city',
            'province:' => '',
            ',province:' => '',
            ',country:' => 'address.country'
        );

        $r = easy_parser($data_str, $items, 'mdy', $extra, false, true);

        foreach ($r as $key => $part)
            if (isset($part['email'])) {
                @list($email, $phone) = explode(' ', $part['email']);
                $email = str_replace('(', '', $email);
                $email = str_replace(')', '', $email);
                $r[$key]['email'] = $email;
                if ($phone != '')
                    $r[$key]['phone'] = $phone;
            }

        return $r;
    }

}
