<?php
namespace packages\whois;
class gtld_handler extends WhoisClient {

    var $REG_FIELDS = array(
        'Domain Name:' => 'regrinfo.domain.name',
        'Registrar:' => 'regyinfo.registrar',
        'Whois Server:' => 'regyinfo.whois',
        'Referral URL:' => 'regyinfo.referrer',
        'Name Server:' => 'regrinfo.domain.nserver.', // identical descriptors
        'Updated Date:' => 'regrinfo.domain.changed',
        'Last Updated On:' => 'regrinfo.domain.changed',
        'EPP Status:' => 'regrinfo.domain.epp_status.',
        'Status:' => 'regrinfo.domain.status.',
        'Creation Date:' => 'regrinfo.domain.created',
        'Created On:' => 'regrinfo.domain.created',
        'Expiration Date:' => 'regrinfo.domain.expires',
        'Registry Expiry Date:' => 'regrinfo.domain.expires',
        'Updated Date:' => 'regrinfo.domain.changed',
        'No match for ' => 'nodomain'
    );

    function parse($data, $query) {
        $this->query = array();
        $this->result = generic_parser_b($data['rawdata'], $this->REG_FIELDS, 'dmy');

        unset($this->result['registered']);

        if (isset($this->result['nodomain'])) {
            unset($this->result['nodomain']);
            $this->result['regrinfo']['registered'] = 'no';
            return $this->result;
        }

        if ($this->deepWhois)
            $this->result = $this->deepWhois($query, $this->result);

        // Next server could fail to return data
        if (empty($this->result['rawdata']) || count($this->result['rawdata']) < 3)
            $this->result['rawdata'] = $data['rawdata'];

        // Domain is registered no matter what next server says
        $this->result['regrinfo']['registered'] = 'yes';

        return $this->result;
    }

}
