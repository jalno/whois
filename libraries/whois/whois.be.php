<?php
namespace packages\whois;
class be_handler {

    function parse($data, $query) {
        $items = array(
            'domain.name' => 'Domain:',
            'domain.status' => 'Status:',
            'domain.nserver' => 'Nameservers:',
            'domain.created' => 'Registered:',
            'owner' => 'Licensee:',
            'admin' => 'Onsite Contacts:',
            'tech' => 'Registrar Technical Contacts:',
            'agent' => 'Registrar:',
            'agent.uri' => 'Website:'
        );

        $trans = array(
            'company name2:' => ''
        );

        $r = array();

        $r['regrinfo'] = get_blocks($data['rawdata'], $items);

        if ($r['regrinfo']['domain']['status'] == 'REGISTERED') {
            $r['regrinfo']['registered'] = 'yes';
            $r['regrinfo'] = get_contacts($r['regrinfo'], $trans);

            if (isset($r['regrinfo']['agent'])) {
                $sponsor = get_contact($r['regrinfo']['agent'], $trans);
                unset($r['regrinfo']['agent']);
                $r['regrinfo']['domain']['sponsor'] = $sponsor;
            }

            $r = format_dates($r, '-mdy');
        } else
            $r['regrinfo']['registered'] = 'no';

        $r['regyinfo']['referrer'] = 'http://www.domain-registry.nl';
        $r['regyinfo']['registrar'] = 'DNS Belgium';
        return $r;
    }

}
