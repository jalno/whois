<?php
namespace packages\whois;
class fm_handler {

    function parse($data, $query) {
        $items = array(
            'owner' => 'Registrant',
            'admin' => 'Admin',
            'tech' => 'Technical',
            'billing' => 'Billing',
            'domain.nserver' => 'Name Servers:',
            'domain.created' => 'Created:',
            'domain.expires' => 'Expires:',
            'domain.changed' => 'Modified:',
            'domain.status' => 'Status:',
            'domain.sponsor' => 'Registrar Name:'
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data['rawdata'], $items);

        $items = array(
            'phone number:' => 'phone',
            'email address:' => 'email',
            'fax number:' => 'fax',
            'organisation:' => 'organization'
        );

        if (!empty($r['regrinfo']['domain']['created'])) {
            $r['regrinfo'] = get_contacts($r['regrinfo'], $items);

            if (count($r['regrinfo']['billing']['address']) > 4)
                $r['regrinfo']['billing']['address'] = array_slice($r['regrinfo']['billing']['address'], 0, 4);

            $r['regrinfo']['registered'] = 'yes';
            format_dates($r['regrinfo']['domain'], 'dmY');
        }
        else {
            $r = '';
            $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo']['referrer'] = 'http://www.dot.dm';
        $r['regyinfo']['registrar'] = 'dotFM';
        return $r;
    }

}
