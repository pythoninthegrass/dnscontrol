package godaddy

import (
	"encoding/json"
	"fmt"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/StackExchange/dnscontrol/v4/pkg/txtutil"
	"github.com/StackExchange/dnscontrol/v4/providers"
	"golang.org/x/net/idna"
)

/*

GoDaddy API DNS provider:

Info required in `creds.json`:
   - api_key
   - api_secret
   - api_url (optional, default: https://api.godaddy.com)

*/

var features = providers.DocumentationNotes{
	providers.CanAutoDNSSEC:          providers.Cannot(),
	providers.CanGetZones:            providers.Cannot(),
	providers.CanUseAlias:            providers.Cannot(),
	providers.CanUseCAA:              providers.Cannot(),
	providers.CanUseDS:               providers.Cannot(),
	providers.CanUseDSForChildren:    providers.Cannot(),
	providers.CanUseLOC:              providers.Cannot(),
	providers.CanUseNAPTR:            providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSOA:              providers.Cannot(),
	providers.CanUseSRV:              providers.Cannot(),
	providers.CanUseSSHFP:            providers.Cannot(),
	providers.CanUseTLSA:             providers.Cannot(),
	providers.DocCreateDomains:       providers.Cannot(),
	providers.DocDualHost:            providers.Cannot(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	fns := providers.DspFuncs{
		Initializer:   New,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType("GODADDY", fns, features)
}

// New creates a new API handle.
func New(settings map[string]string, _ json.RawMessage) (providers.DNSServiceProvider, error) {
	apiKey := settings["api_key"]
	apiSecret := settings["api_secret"]
	apiUrl := settings["api_url"]

	if apiKey == "" {
		return nil, fmt.Errorf("missing GODADDY api_key")
	}
	if apiSecret == "" {
		return nil, fmt.Errorf("missing GODADDY api_secret")
	}
	if apiUrl == "" {
		apiUrl = "https://api.godaddy.com"
	}

	return &godaddyProvider{
		apiKey:    apiKey,
		apiSecret: apiSecret,
	}, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (api *godaddyProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, error) {
	//Saw this for some providers but not all, required?
	txtutil.SplitSingleLongTxt(dc.Records) // Autosplit long TXT records

	checkModifications(dc)

	// GoDaddy is a "ByRecord" API.
	instructions, err := diff2.ByRecord(existingRecords, dc, nil)
	if err != nil {
		return nil, err
	}

	var corrections []*models.Correction

	for _, inst := range instructions {
		//fmt.Printf("%s", inst.String())

		domain := dc.Name
		msg := inst.Msgs[0]
		printer.Warnf("%s\n", msg)

		var corrs *models.Correction

		switch inst.Type {
		case diff2.CREATE:
			createRec := inst.New[0]
			corrs = &models.Correction{Msg: msg, F: func() error { return api.create(createRec, dc.Name) }}
		case diff2.CHANGE:
			newrec := inst.New[0]
			oldrec := inst.Old[0]
			corrs = &models.Correction{Msg: msg, F: func() error { return api.update(oldrec, newrec, domain) }}
		case diff2.DELETE:
			deleteRec := inst.Old[0]
			corrs = &models.Correction{Msg: msg, F: func() error { return api.delete(deleteRec, domain) }}
		default:
			fmt.Printf("Found missing type %s\n", inst.Type)
		}

		corrections = append(corrections, corrs)
	}

	return corrections, nil
}

// GetNameservers returns the nameservers for a domain.
func (api *godaddyProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	details, err := api.getNameserversForDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("Couldn't get nameservers for domain '%s': %s", domain, err)
	}
	return details, nil
} //fmt.Printf("Create record %s of type %s with data: %s\n", createRec.Name, createRec.Type, createRec.GetTargetField())

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (api *godaddyProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	records, err := api.getAll(domain)
	if err != nil {
		return nil, fmt.Errorf("Unable to fetch all records for domain '%s': %s", domain, err)
	}
	return records, nil
}

func checkModifications(dc *models.DomainConfig) {
	newList := make([]*models.RecordConfig, 0, len(dc.Records))

	punyRoot, err := idna.ToASCII(dc.Name)
	if err != nil {
		punyRoot = dc.Name
	}

	for _, rec := range dc.Records {
		if rec.Type == "NS" && rec.GetLabelFQDN() == punyRoot {
			//printer.Debugf("godaddy does not support modifying NS records on base domain. %s will not be added.\n", rec.GetTargetField())
			continue
		}
		if rec.Type == "MX" || rec.Type == "CNAME" {
			fmt.Printf("Data: %s", rec.GetTargetField())
		}
		newList = append(newList, rec)
	}
	dc.Records = newList
}