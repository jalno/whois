<?php
namespace packages\whois;
class uk_handler {

    function parse($data_str, $query) {
        $items = array(
            'owner.organization' => 'Registrant:',
            'owner.address' => "Registrant's address:",
            'owner.type' => 'Registrant type:',
            'domain.created' => 'Registered on:',
            'domain.changed' => 'Last updated:',
            'domain.expires' => 'Renewal date:',
            'domain.nserver' => 'Name servers:',
            'domain.sponsor' => 'Registrar:',
            'domain.status' => 'Registration status:',
            'domain.dnssec' => 'DNSSEC:',
            '' => 'WHOIS lookup made at',
            'disclaimer' => '--',
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data_str['rawdata'], $items);

        if (isset($r['regrinfo']['owner'])) {
            $r['regrinfo']['owner']['organization'] = $r['regrinfo']['owner']['organization'][0];
            $r['regrinfo']['domain']['sponsor'] = $r['regrinfo']['domain']['sponsor'][0];
            $r['regrinfo']['registered'] = 'yes';

            $r = format_dates($r, 'dmy');
        } else {
            if (strpos($data_str['rawdata'][1], 'Error for ')) {
                $r['regrinfo']['registered'] = 'yes';
                $r['regrinfo']['domain']['status'] = 'invalid';
            } else
                $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo'] = array(
            'referrer' => 'http://www.nominet.org.uk',
            'registrar' => 'Nominet UK'
        );
        return $r;
    }

}
