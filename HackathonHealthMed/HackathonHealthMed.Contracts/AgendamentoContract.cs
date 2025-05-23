﻿using System.ComponentModel.DataAnnotations;

namespace HackathonHealthMed.Contracts
{
    public class AgendamentoContract
    {
        [Required]
        public Guid Id { get; set; }

        [Required(ErrorMessage = "O ID do paciente é obrigatório")]
        public Guid PacienteId { get; set; }

        [Required(ErrorMessage = "O ID do Horário da Consulta é obrigatório")]
        public Guid HorarioConsultaId { get; set; }

        [Required]
        public StatusAgendamento Status { get; set; }

        [MaxLength(200)]
        public string? Justificativa { get; set; }

        [Required]
        public string MedicoCrm { get; set; }
    }

    public enum StatusAgendamento
    {
        Confirmado,
        Cancelado,
        Pendente,
        Recusado
    }
}
