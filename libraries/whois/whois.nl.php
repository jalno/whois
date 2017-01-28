<?php
namespace packages\whois;
class nl_handler {

    function parse($data, $query) {
        $items = array(
            'domain.name' => 'Domain name:',
            'domain.status' => 'Status:',
            'domain.nserver' => 'Domain nameservers:',
            'domain.created' => 'Date registered:',
            'domain.changed' => 'Record last updated:',
            'domain.sponsor' => 'Registrar:',
            'admin' => 'Administrative contact:',
            'tech' => 'Technical contact(s):'
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data['rawdata'], $items);
        $r['regyinfo']['referrer'] = 'http://www.domain-registry.nl';
        $r['regyinfo']['registrar'] = 'Stichting Internet Domeinregistratie NL';

        if (!isset($r['regrinfo']['domain']['status'])) {
            $r['regrinfo']['registered'] = 'no';
            return $r;
        }

        if (isset($r['regrinfo']['tech']))
            $r['regrinfo']['tech'] = $this->get_contact($r['regrinfo']['tech']);

        if (isset($r['regrinfo']['zone']))
            $r['regrinfo']['zone'] = $this->get_contact($r['regrinfo']['zone']);

        if (isset($r['regrinfo']['admin']))
            $r['regrinfo']['admin'] = $this->get_contact($r['regrinfo']['admin']);

        if (isset($r['regrinfo']['owner']))
            $r['regrinfo']['owner'] = $this->get_contact($r['regrinfo']['owner']);

        $r['regrinfo']['registered'] = 'yes';
        format_dates($r, 'dmy');
        return $r;
    }

    function get_contact($data) {
        $r = get_contact($data);

        if (isset($r['name']) && preg_match('/^[A-Z0-9]+-[A-Z0-9]+$/', $r['name'])) {
            $r['handle'] = $r['name'];
            $r['name'] = array_shift($r['address']);
        }

        return $r;
    }

}
