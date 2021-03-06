//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vhudson-jaxb-ri-2.1-558 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2011.11.27 at 11:03:36 AM CET 
//


package org.sinekarta.alfresco.model.agenziaEntrate;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for DatiAnagrType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DatiAnagrType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{}CodFisc"/>
 *         &lt;choice>
 *           &lt;element ref="{}DatiPersonaFisica"/>
 *           &lt;element ref="{}Denominazione"/>
 *         &lt;/choice>
 *         &lt;element ref="{}DomFiscaleSedeLegale"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DatiAnagrType", propOrder = {
    "codFisc",
    "datiPersonaFisica",
    "denominazione",
    "domFiscaleSedeLegale"
})
@XmlRootElement(name = "DatiAnagr")
public class DatiAnagrType implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@XmlTransient
	private String personaODenominazione;

    @XmlElement(name = "CodFisc", required = true)
    protected String codFisc;
    @XmlElement(name = "DatiPersonaFisica")
    protected DatiPersonaFisica datiPersonaFisica;
    @XmlElement(name = "Denominazione")
    protected String denominazione;
    @XmlElement(name = "DomFiscaleSedeLegale", required = true)
    protected DomFiscaleSedeLegale domFiscaleSedeLegale;

    /**
     * Gets the value of the codFisc property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCodFisc() {
        return codFisc;
    }

    /**
     * Sets the value of the codFisc property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCodFisc(String value) {
        this.codFisc = value;
    }

    /**
     * Gets the value of the datiPersonaFisica property.
     * 
     * @return
     *     possible object is
     *     {@link DatiPersonaFisica }
     *     
     */
    public DatiPersonaFisica getDatiPersonaFisica() {
        return datiPersonaFisica;
    }

    /**
     * Sets the value of the datiPersonaFisica property.
     * 
     * @param value
     *     allowed object is
     *     {@link DatiPersonaFisica }
     *     
     */
    public void setDatiPersonaFisica(DatiPersonaFisica value) {
        this.datiPersonaFisica = value;
    }

    /**
     * Gets the value of the denominazione property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDenominazione() {
        return denominazione;
    }

    /**
     * Sets the value of the denominazione property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDenominazione(String value) {
        this.denominazione = value;
    }

    /**
     * Gets the value of the domFiscaleSedeLegale property.
     * 
     * @return
     *     possible object is
     *     {@link DomFiscaleSedeLegale }
     *     
     */
    public DomFiscaleSedeLegale getDomFiscaleSedeLegale() {
        return domFiscaleSedeLegale;
    }

    /**
     * Sets the value of the domFiscaleSedeLegale property.
     * 
     * @param value
     *     allowed object is
     *     {@link DomFiscaleSedeLegale }
     *     
     */
    public void setDomFiscaleSedeLegale(DomFiscaleSedeLegale value) {
        this.domFiscaleSedeLegale = value;
    }

	public String getPersonaODenominazione() {
		return personaODenominazione;
	}

	public void setPersonaODenominazione(String personaODenominazione) {
		this.personaODenominazione = personaODenominazione;
	}

}
